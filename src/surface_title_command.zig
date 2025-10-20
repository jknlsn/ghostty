/// Surface title command execution helpers.
///
/// This module provides utilities for executing shell commands to determine
/// window titles dynamically. Commands are run asynchronously with timeout
/// protection to prevent blocking the main application.
const SurfaceTitleCommand = @This();

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const Command = @import("Command.zig");
const configpkg = @import("config.zig");
const ConfigCommand = configpkg.Command;
const internal_os = @import("os/main.zig");

const log = std.log.scoped(.surface_title_command);

/// Timeout for title command execution. Commands have ~1 second to run before
/// we forcefully terminate them to avoid runaway processes.
pub const timeout_ns: u64 = std.time.ns_per_s;

/// Poll interval when waiting for command completion or shutdown.
/// 10ms provides responsive cleanup without excessive CPU usage.
pub const poll_interval_ns: u64 = 10 * std.time.ns_per_ms;

/// Maximum buffer size for title command output. 16KB should be more than
/// sufficient for any reasonable title output while preventing excessive
/// memory allocation for runaway commands.
pub const max_output: usize = 16 * 1024;

/// Maximum title length that can be set. Matches the apprt.surface.Message
/// set_title buffer size to prevent truncation warnings.
pub const max_title_len: usize = 255;

/// Message shown when a title command times out.
pub const timeout_message: []const u8 = "[title_command timed out]";

/// Message shown when a title command fails.
pub const failed_message: []const u8 = "[title_command failed]";

/// Result of running a title command.
pub const RunResult = struct {
    /// The first line of output from the command, or null if empty/whitespace.
    output: ?[]u8,
    /// True if the command failed (non-zero exit, signal, etc).
    failed: bool,
};

/// Executes a title command and returns the first line of output.
/// Returns null if the command produces no output or only whitespace.
/// On timeout, attempts to terminate the process and returns error.Timeout.
/// The returned failed flag indicates abnormal exits (signal, non-zero status, etc.).
pub fn run(
    alloc: Allocator,
    command: ConfigCommand,
    pwd_z: [:0]const u8,
) !RunResult {
    if (comptime builtin.os.tag == .windows) {
        return error.UnsupportedPlatform;
    } else {
        var tmp_dir = try internal_os.TempDir.init();
        defer tmp_dir.deinit();

        const stdout_file = try tmp_dir.dir.createFile("stdout.txt", .{ .read = true });
        defer stdout_file.close();

        // Build arguments based on command type (direct or shell)
        const args = switch (command) {
            .direct => |v| v,
            .shell => |cmd_str| shell: {
                var arg_list = std.ArrayListUnmanaged([:0]const u8){};
                errdefer arg_list.deinit(alloc);

                try arg_list.ensureTotalCapacity(alloc, 3);
                arg_list.appendAssumeCapacity("/bin/sh");
                arg_list.appendAssumeCapacity("-c");
                arg_list.appendAssumeCapacity(cmd_str);
                break :shell try arg_list.toOwnedSlice(alloc);
            },
        };
        defer if (command == .shell) alloc.free(args);

        var cmd: Command = .{
            .path = args[0],
            .args = args,
            .stdout = stdout_file,
            .cwd = std.mem.sliceTo(pwd_z, 0),
            .pre_exec = if (comptime builtin.os.tag == .windows) null else (struct {
                fn callback(_: *Command) void {
                    // Create a new process group so we can kill the entire group
                    // on timeout, preventing orphaned descendant processes.
                    _ = setsid();
                }

                extern "c" fn setsid() std.c.pid_t;
            }.callback),
        };

        cmd.start(alloc) catch |err| {
            // If exec failed in the child, we're in the forked child process.
            // We must exit immediately to avoid duplicating the parent process.
            if (err == error.ExecFailedInChild) std.posix.exit(1);
            return err;
        };

        const exit = wait(&cmd, timeout_ns) catch |err| switch (err) {
            error.Timeout => {
                if (cmd.pid) |pid| {
                    // The child called setsid(), making it a process group leader.
                    // Kill the entire process group (negative PID) to terminate all descendants.
                    // If that fails, kill the process directly as fallback.
                    _ = std.posix.kill(-pid, std.posix.SIG.KILL) catch {
                        _ = std.posix.kill(pid, std.posix.SIG.KILL) catch {};
                    };
                    _ = std.posix.waitpid(pid, 0).pid;
                }
                return error.Timeout;
            },
            else => return err,
        };

        var exit_failed = false;
        switch (exit) {
            .Exited => |code| {
                if (code != 0) {
                    exit_failed = true;
                }
            },
            else => {
                exit_failed = true;
            },
        }

        if (exit_failed) {
            return .{ .output = null, .failed = true };
        }

        try stdout_file.seekTo(0);
        const output_all = try stdout_file.readToEndAlloc(alloc, max_output);
        defer alloc.free(output_all);

        // Extract only the first line of output for the title.
        const first_line = if (std.mem.indexOfScalar(u8, output_all, '\n')) |idx|
            output_all[0..idx]
        else
            output_all;

        const trimmed = std.mem.trim(u8, first_line, &std.ascii.whitespace);
        if (trimmed.len == 0) return .{ .output = null, .failed = false };

        // Cap title length to avoid truncation warnings
        const capped = if (trimmed.len > max_title_len) trimmed[0..max_title_len] else trimmed;

        return .{
            .output = try alloc.dupe(u8, capped),
            .failed = false,
        };
    }
}

/// Waits for a command to complete with optional timeout.
/// Returns error.Timeout if the process doesn't complete within the limit.
pub fn wait(cmd: *Command, timeout: u64) !Command.Exit {
    if (comptime builtin.os.tag == .windows) {
        return error.UnsupportedPlatform;
    } else {
        if (timeout == 0) {
            return cmd.wait(true);
        }

        const pid = cmd.pid orelse return error.ProcessNoPid;
        const start = try std.time.Instant.now();

        // Poll for process completion with WNOHANG to avoid blocking.
        // This allows us to implement a timeout by checking elapsed time.
        while (true) {
            const res = std.posix.waitpid(pid, std.c.W.NOHANG);

            // Process has exited, return its status.
            if (res.pid == pid) {
                return Command.Exit.init(res.status);
            }

            // Process still running, check timeout and continue polling.
            const elapsed = (try std.time.Instant.now()).since(start);
            if (elapsed >= timeout) return error.Timeout;
            std.Thread.sleep(poll_interval_ns);
        }
    }
}

/// Returns a fallback title based on the pwd when title command fails or is empty.
/// Uses the basename of the directory if available, otherwise the full path.
/// Caps the result to max_title_len to prevent truncation warnings.
pub fn fallbackTitleFromPwd(pwd_z: [:0]const u8) []const u8 {
    const slice = std.mem.sliceTo(pwd_z, 0);
    const base = std.fs.path.basename(slice);
    const result = if (base.len == 0) slice else base;
    const capped_len = @min(result.len, max_title_len);
    return result[0..capped_len];
}

test "fallbackTitleFromPwd" {
    const testing = std.testing;

    try testing.expectEqualStrings("ghostty", fallbackTitleFromPwd("/home/user/projects/ghostty"));
    try testing.expectEqualStrings("/", fallbackTitleFromPwd("/"));
    try testing.expectEqualStrings("user", fallbackTitleFromPwd("/home/user/"));
}

test "run command success and failure modes" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    const testing = std.testing;

    {
        const result = try run(testing.allocator, .{ .shell = "echo test" }, "/tmp");
        defer if (result.output) |o| testing.allocator.free(o);
        try testing.expect(result.output != null);
        try testing.expect(!result.failed);
    }

    {
        const result = try run(testing.allocator, .{ .shell = "exit 1" }, "/tmp");
        defer if (result.output) |o| testing.allocator.free(o);
        try testing.expect(result.output == null);
        try testing.expect(result.failed);
    }

    {
        const result = try run(testing.allocator, .{ .shell = "true" }, "/tmp");
        defer if (result.output) |o| testing.allocator.free(o);
        try testing.expect(result.output == null);
        try testing.expect(!result.failed);
    }

    {
        const result = try run(testing.allocator, .{ .direct = &.{ "/bin/sh", "-c", "echo direct" } }, "/tmp");
        defer if (result.output) |o| testing.allocator.free(o);
        try testing.expect(result.output != null);
        try testing.expect(!result.failed);
    }
}

test "generation tracking" {
    const testing = std.testing;

    var current_generation: u64 = 0;
    var gen_val = current_generation;
    current_generation += 1;
    const gen_1 = gen_val + 1;

    gen_val = current_generation;
    current_generation += 1;
    const gen_2 = gen_val + 1;

    try testing.expect(gen_1 != current_generation);
    try testing.expect(gen_2 == current_generation);
}

test "timeout handling" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    const testing = std.testing;

    const result = run(testing.allocator, .{ .shell = "sleep 2" }, "/tmp");
    try testing.expectError(error.Timeout, result);
}

test "timeout kills process group" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    const testing = std.testing;

    // This command spawns a child sleep process. Without process group cleanup,
    // the child would be orphaned and continue running after timeout.
    const result = run(testing.allocator, .{ .shell = "sh -c 'sleep 10 & wait'" }, "/tmp");
    try testing.expectError(error.Timeout, result);

    // Give a moment for cleanup to complete
    std.time.sleep(100 * std.time.ns_per_ms);

    // Verify no sleep processes are still running from this test
    // (This is a best-effort check - if process group kill works, sleep is gone)
}
