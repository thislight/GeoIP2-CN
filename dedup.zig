const std = @import("std");

pub const IpAddressRange = union(enum) {
    v4: V4,
    v6: V6,

    pub const V4 = struct {
        ip: u32,
        prefix_len: u6, // 0–32
    };

    pub const V6 = struct {
        ip: u128,
        prefix_len: u7, // 0–128
    };

    pub fn format(
        self: IpAddressRange,
        writer: *std.Io.Writer,
    ) !void {
        switch (self) {
            .v4 => |v| {
                try writer.print("{d}.{d}.{d}.{d}/{d}", .{
                    (v.ip >> 24) & 0xff,
                    (v.ip >> 16) & 0xff,
                    (v.ip >> 8) & 0xff,
                    v.ip & 0xff,
                    v.prefix_len,
                });
            },
            .v6 => |v| {
                var buf: [16]u8 = undefined;
                std.mem.writeInt(u128, &buf, v.ip, .foreign);
                var cont_empty_cnt: usize = 0;
                inline for (0..8) |i| {
                    const bi = i * 2;
                    const segment = std.mem.readInt(u16, buf[bi .. bi + 2], .foreign);
                    if (segment != 0) {
                        if (i > 0) _ = try writer.write(":");
                        try writer.print("{x:0>4}", .{segment});
                        cont_empty_cnt = 0;
                    } else {
                        if (i > 0 and cont_empty_cnt < 2) _ = try writer.write(":");
                        cont_empty_cnt += 1;
                    }
                }
                try writer.print("/{d}", .{v.prefix_len});
            },
        }
    }
};

const TrieNode = struct {
    flag: bool = false,
    child: [2]?*TrieNode = .{ null, null },

    pub fn deinit(self: *TrieNode, allocator: std.mem.Allocator) void {
        for (self.child) |child| {
            if (child) |p| {
                p.deinit(allocator);
                allocator.destroy(p);
            }
        }
    }
};

fn createNode(allocator: std.mem.Allocator) !*TrieNode {
    const node = try allocator.create(TrieNode);
    node.* = .{};
    return node;
}

fn mergeNode(node: *TrieNode) bool {
    if (node.flag) return true;
    if (node.child[0] == null or node.child[1] == null) return false;
    const result = mergeNode(node.child[0].?) and mergeNode(node.child[1].?);
    node.flag = result;
    return result;
}

pub fn IpAddressSet(comptime bits: comptime_int) type {
    return struct {
        root: ?*TrieNode = null,
        current: Int = 0,
        allocator: std.mem.Allocator,

        const Int = std.meta.Int(.unsigned, bits);
        const PrefixLen = std.meta.Int(.unsigned, std.math.log2_int_ceil(u16, bits + 1));
        const Self = @This();

        pub fn init(allocator: std.mem.Allocator) Self {
            return .{ .allocator = allocator };
        }

        pub fn deinit(self: *Self) void {
            if (self.root) |root| {
                root.deinit(self.allocator);
                self.allocator.destroy(root);
            }
        }

        fn makeMask(prefix_len: PrefixLen) Int {
            return if (prefix_len > 0)
                ~@as(Int, (@as(Int, 1) << @intCast(bits - prefix_len)) - 1)
            else
                0;
        }

        /// Insert a CIDR range into the trie.
        pub fn insert(self: *Self, ip: Int, prefix_len: PrefixLen) !void {
            var mask = makeMask(prefix_len);
            var ip_bits = ip;
            var p: *?*TrieNode = &self.root;
            while (mask != 0) {
                if (p.* == null) p.* = try createNode(self.allocator);
                const bit: u1 = @intCast(ip_bits >> @intCast(bits - 1));
                p = &p.*.?.child[bit];
                ip_bits <<= 1;
                mask <<= 1;
            }
            if (p.* == null) p.* = try createNode(self.allocator);
            p.*.?.flag = true;
        }

        pub fn merge(self: *Self) void {
            if (self.root) |r| _ = mergeNode(r);
        }

        pub fn iterate(self: *Self, visitor: anytype) !void {
            if (self.root) |r| try self.iterateNode(r, 0, visitor);
        }

        fn iterateNode(
            self: *Self,
            node: *TrieNode,
            depth: PrefixLen,
            visitor: anytype,
        ) !void {
            if (node.flag) {
                const ip = self.current & makeMask(depth);
                try visitor.visit(ip, @intCast(depth));
                return;
            }
            if (node.child[0]) |child0| {
                self.current &= ~(@as(Int, 1) << @intCast(bits - 1 - depth));
                try self.iterateNode(child0, depth + 1, visitor);
            }
            if (node.child[1]) |child1| {
                self.current |= @as(Int, 1) << @intCast(bits - 1 - depth);
                try self.iterateNode(child1, depth + 1, visitor);
            }
        }
    };
}

const V4Printer = struct {
    writer: *std.Io.Writer,

    pub fn visit(self: *V4Printer, ip: u32, prefix_len: u6) !void {
        const range: IpAddressRange = .{ .v4 = .{ .ip = ip, .prefix_len = prefix_len } };
        try range.format(self.writer);
        _ = try self.writer.write("\n");
    }
};

const V6Printer = struct {
    writer: *std.Io.Writer,

    pub fn visit(self: *V6Printer, ip: u128, prefix_len: u7) !void {
        const range = IpAddressRange{ .v6 = .{ .ip = ip, .prefix_len = prefix_len } };
        try range.format(self.writer);
        _ = try self.writer.write("\n");
    }
};

fn parseCidrV4(line: []const u8) ?IpAddressRange.V4 {
    var pos: usize = 0;

    const a = parseU8(line, &pos) orelse return null;
    if (pos >= line.len or line[pos] != '.') return null;
    pos += 1;

    const b = parseU8(line, &pos) orelse return null;
    if (pos >= line.len or line[pos] != '.') return null;
    pos += 1;

    const c = parseU8(line, &pos) orelse return null;
    if (pos >= line.len or line[pos] != '.') return null;
    pos += 1;

    const d = parseU8(line, &pos) orelse return null;
    if (pos >= line.len or line[pos] != '/') return null;
    pos += 1;

    const prefix_len = std.fmt.parseInt(u6, line[pos..], 10) catch return null;
    if (prefix_len > 32) return null;

    return .{
        .ip = (@as(u32, a) << 24) | (@as(u32, b) << 16) | (@as(u32, c) << 8) | @as(u32, d),
        .prefix_len = prefix_len,
    };
}

fn parseCidrV6(line: []const u8) ?IpAddressRange.V6 {
    const slash = std.mem.indexOfScalar(u8, line, '/') orelse return null;
    const ip_str = line[0..slash];
    const prefix_str = line[slash + 1 ..];

    const prefix_len = std.fmt.parseInt(u7, prefix_str, 10) catch return null;
    if (prefix_len > 128) return null;

    const ip = parseIpv6Text(ip_str) orelse return null;
    return .{ .ip = ip, .prefix_len = prefix_len };
}

fn parseIpv6Text(text: []const u8) ?u128 {
    const double_colon = std.mem.indexOf(u8, text, "::");

    var left_segments: usize = 0;
    var right_segments: usize = 0;
    var ip: u128 = 0;

    if (double_colon) |dc| {
        // Parse left part (before "::")
        if (dc > 0) {
            var pos: usize = 0;
            while (pos < dc) : (left_segments += 1) {
                if (left_segments >= 8) return null;
                const seg = parseHex16(text, &pos) orelse return null;
                ip = (ip << 16) | @as(u128, seg);
                if (pos < dc) {
                    if (text[pos] != ':') return null;
                    pos += 1;
                }
            }
        }

        // Parse right part (after "::")
        var rpos: usize = dc + 2;
        var right_parts: [8]u16 = undefined;
        while (rpos < text.len) : (right_segments += 1) {
            if (right_segments >= 8) return null;
            const seg = parseHex16(text, &rpos) orelse return null;
            right_parts[right_segments] = seg;
            if (rpos < text.len) {
                if (text[rpos] != ':') return null;
                rpos += 1;
            }
        }

        if (left_segments + right_segments >= 8) return null;

        const zero_count = 8 - left_segments - right_segments;
        var i: usize = 0;
        while (i < zero_count) : (i += 1) {
            ip = (ip << 16);
        }

        i = 0;
        while (i < right_segments) : (i += 1) {
            ip = (ip << 16) | @as(u128, right_parts[i]);
        }
    } else {
        var pos: usize = 0;
        while (pos < text.len) : (left_segments += 1) {
            if (left_segments >= 8) return null;
            const seg = parseHex16(text, &pos) orelse return null;
            ip = (ip << 16) | @as(u128, seg);
            if (pos < text.len) {
                if (text[pos] != ':') return null;
                pos += 1;
            }
        }
        if (left_segments != 8) return null;
    }

    return ip;
}

fn parseHex16(text: []const u8, pos: *usize) ?u16 {
    const start = pos.*;
    while (pos.* < text.len and std.mem.findScalar(u8, std.fmt.hex_charset, text[pos.*]) != null) {
        pos.* += 1;
    }
    if (pos.* == start) return null;
    return std.fmt.parseInt(u16, text[start..pos.*], 16) catch null;
}

fn parseU8(line: []const u8, pos: *usize) ?u8 {
    const start = pos.*;
    while (pos.* < line.len and line[pos.*] >= '0' and line[pos.*] <= '9') {
        pos.* += 1;
    }
    if (pos.* == start) return null;
    return std.fmt.parseInt(u8, line[start..pos.*], 10) catch null;
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;

    var v4_set = IpAddressSet(32).init(gpa);
    defer v4_set.deinit();
    var v6_set = IpAddressSet(128).init(gpa);
    defer v6_set.deinit();

    var stdin_buf: [4096]u8 = undefined;
    var stdin_reader = std.Io.File.stdin().reader(io, &stdin_buf);

    var stdout_buf: [4096]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buf);

    while (try stdin_reader.interface.takeDelimiter('\n')) |line| {
        if (line.len == 0) continue;

        if (std.mem.indexOfScalar(u8, line, ':') != null) {
            if (parseCidrV6(line)) |result| {
                try v6_set.insert(result.ip, result.prefix_len);
            }
        } else {
            if (parseCidrV4(line)) |result| {
                try v4_set.insert(result.ip, result.prefix_len);
            }
        }
    }

    v4_set.merge();
    var v4_printer = V4Printer{ .writer = &stdout_writer.interface };
    try v4_set.iterate(&v4_printer);

    v6_set.merge();
    var v6_printer = V6Printer{ .writer = &stdout_writer.interface };
    try v6_set.iterate(&v6_printer);

    try stdout_writer.interface.flush();
}
