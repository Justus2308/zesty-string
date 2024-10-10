const builtin = @import("builtin");
const std = @import("std");

const math = std.math;
const mem = std.mem;
const testing = std.testing;

const Allocator = std.mem.Allocator;
const StructField = std.builtin.Type.StructField;

const assert = std.debug.assert;
const log = std.log.scoped(.zesty_string);

const native_endian = builtin.cpu.arch.endian();


pub const usizeMinusOne = std.meta.Int(.unsigned, @bitSizeOf(usize)-1);


pub const Config = struct {
	grow_eagerly: bool = true,
	shrink_eagerly: bool = false,
	log_level: std.log.Level = .debug,
};
/// `config` only affects the runtime growing/shrinking behavior of the type,
/// it is safe to cast from one `ZestyString` configuration to another.
pub fn ZestyString(comptime config: Config) type {
	return extern union {
		long: Self.Long,
		short: Self.Short,
		any: Self.Any,


		const Self = @This();

		const Long = extern struct {
			ptr: [*]u8,
			cap_plus_is_owner: Self.SizeWithFlag,
			len_plus_tag: Self.SizeWithFlag,

			pub inline fn init(
				ptr: [*]u8,
				capacity: usizeMinusOne,
				length: usizeMinusOne,
				is_owner: bool,
			) Self.Long {
				assert(length <= capacity);
				return .{
					.ptr = ptr,
					.cap_plus_is_owner = .{ .size = capacity, .flag = @intFromBool(is_owner) },
					.len_plus_tag = .{ .size = length, .flag = @intFromEnum(Tag.long) },
				};
			}

			pub inline fn cap(long: *const Self.Long) usizeMinusOne {
				return long.cap_plus_is_owner.size;
			}
			pub inline fn len(long: *const Self.Long) usizeMinusOne {
				return long.len_plus_tag.size;
			}

			pub inline fn setCap(long: *Self.Long, capacity: usizeMinusOne) void {
				long.cap_plus_is_owner.size = capacity;
			}
			pub inline fn setLen(long: *Self.Long, length: usizeMinusOne) void {
				long.len_plus_tag.size = length;
			}
		};

		const Short = extern union {
			str: [Self.max_short_size:0]u8,
			any: Self.Any,

			pub inline fn init(string: []const u8) Self.Short {
				assert(string.len <= Self.max_short_size);
				var short: Self.Short = undefined;
				@memcpy(short.str[0..string.len], string);
				short.str[string.len] = 0;
				short.str[Self.max_short_size] = 0;
				return short;
			}

			pub inline fn len(short: *const Self.Short) usizeMinusOne {
				return @intCast(mem.indexOfSentinel(u8, 0, &short.str));
			}
		};

		const Any = extern struct {
			_1: [2]usize,
			padding_plus_tag: Self.SizeWithFlag,

			pub inline fn tag(any: *const Any) Self.Tag {
				return @enumFromInt(any.padding_plus_tag.flag);
			}
		};

		pub const Tag = enum(u1) {
			short = 0,
			long = 1,
		};

		pub const Kind = enum(u2) {
			local = 0b00,
			remote = 0b01,
			heap = 0b11,

			pub inline fn fromBits(tag_bit: u1, is_owner_bit: u1) Self.Kind {
				return @enumFromInt(@as(u2, tag_bit) | ((@as(u2, is_owner_bit & tag_bit)) << 1));
			}
		};

		const SizeWithFlag = @Type(.{ .@"struct" = .{
			.layout = .@"packed",
			.backing_integer = usize,
			.decls = &.{},
			.is_tuple = false,
			.fields = blk: {
				const size_field = StructField{
					.name = "size",
					.type = usizeMinusOne,
					.default_value = null,
					.is_comptime = false,
					.alignment = 0,
				};
				const flag_field = StructField{
					.name = "flag",
					.type = u1,
					.default_value = null,
					.is_comptime = false,
					.alignment = 0,
				};
				const fields: [2]StructField = switch (native_endian) {
					.big => .{ flag_field, size_field },
					.little => .{ size_field, flag_field },
				};
				break :blk &fields;
			},
		}});


		pub const max_size: usizeMinusOne = math.maxInt(usizeMinusOne);
		pub const max_short_size: usizeMinusOne = @divExact(@bitSizeOf(Self.Long), 8) - 1;

		comptime {
			assert(@bitSizeOf(Self.Long) == @bitSizeOf(Self.Short));
			assert(@bitSizeOf(Self.Short) == @bitSizeOf(Self.Any));
			assert(@bitSizeOf(Self.Any) == @bitSizeOf(Self));

			assert(@sizeOf(Self) == @divExact(@bitSizeOf(Self), 8));
			assert(@bitSizeOf(Self) == 3*@bitSizeOf(usize));
		}


		pub const empty = Self{ .any = .{
			._1 = .{ 0, 0 },
			.padding_plus_tag = .{
				.size = 0,
				.flag = @intFromEnum(Tag.short),
			},
		}};


		pub fn initCapacity(allocator: Allocator, capacity: usizeMinusOne) Allocator.Error!Self {
			return if (Self.fitsInShort(capacity)) Self.empty else Self.createLong(allocator, capacity);
		}

		pub fn fromString(allocator: Allocator, string: []const u8) Allocator.Error!Self {
			if (Self.fitsInShort(@intCast(string.len)))
				return .{ .short = Self.Short.init(string) }
			else
				return .{ .long = Self.Long.init(
					(try allocator.dupe(u8, string)).ptr,
					@intCast(string.len),
					@intCast(string.len),
					true,
				)};
		}

		pub fn initBuffer(buffer: []u8, used: usizeMinusOne) Self {
			assert(used <= buffer.len);
			return .{ .long = Self.Long.init(
				buffer.ptr,
				@intCast(buffer.len),
				used,
				false,
			)};
		}

		/// Safe to use on any `Kind` of string.
		pub fn deinit(zs: *Self, allocator: Allocator) void {
			if (zs.kind() == .heap) {
				allocator.free(zs.long.ptr[0..zs.long.cap()]);
			}
			zs.* = undefined;
		}

		pub inline fn kind(zs: *const Self) Self.Kind {
			return Self.Kind.fromBits(
				zs.long.len_plus_tag.flag,
				zs.long.cap_plus_is_owner.flag,
			);
		}

		pub inline fn tag(zs: *const Self) Self.Tag {
			return zs.any.tag();
		}

		pub fn len(zs: *const Self) usizeMinusOne {
			return switch (zs.tag()) {
				.short => zs.short.len(),
				.long => zs.long.len(),
			};
		}
		pub fn cap(zs: *const Self) usizeMinusOne {
			return switch (zs.tag()) {
				.short => Self.max_short_size,
				.long => zs.long.cap(),
			};
		}

		pub fn raw(zs: *const Self) []const u8 {
			return switch (zs.tag()) {
				.short => zs.short.str[0..zs.short.len()],
				.long => zs.long.ptr[0..zs.long.len()],
			};
		}


		pub const CloneOptions = struct {
			truncate: bool = true,
			copy_remotes: bool = false,
		};
		pub fn clone(zs: *const Self, allocator: Allocator, options: CloneOptions) Allocator.Error!Self {
			switch (zs.kind()) {
				.local => return zs.*,
				.remote => if (options.copy_remotes) {
					if (fitsInShort(zs.long.len())
						and (options.truncate or fitsInShort(zs.long.cap()))
					) {
						return .{ .short = Self.Short.init(zs.long.ptr[0..zs.long.len()]) };
					}
				} else {
					return zs.*;
				},
				.heap => {},
			}
			const dupe_size = if (options.truncate) zs.long.len() else zs.long.cap();
			return .{ .long = Self.Long.init(
				(try allocator.dupe(u8, zs.long.ptr[0..dupe_size])).ptr,
				dupe_size,
				zs.long.len(),
				true,
			)};
		}


		pub fn insert(
			zs: *Self,
			allocator: Allocator,
			i: usizeMinusOne,
			string: []const u8,
		) Allocator.Error!void {
			const old_len = zs.len();
			assert(i <= old_len);

			const new_len = zs.len() + @as(usizeMinusOne, @intCast(string.len));
			const move_idx = i + @as(usizeMinusOne, @intCast(string.len));

			const memory: []u8 = blk: {
				switch (zs.kind()) {
					.local => if (Self.fitsInShort(new_len)) {
						const str_ptr = &zs.short.str;
						str_ptr[new_len] = 0;
						break :blk str_ptr[0..new_len];
					} else {
						const new_cap = Self.goodGrowSize(new_len);
						try zs.localToHeap(allocator, new_cap);
					},
					.remote => if (zs.long.cap() < new_len) return Allocator.Error.OutOfMemory,
					.heap => if (zs.long.cap() < new_len) {
						const new_cap = Self.goodGrowSize(new_len);
						try zs.heapResize(allocator, new_cap);
					},
				}
				zs.long.setLen(new_len);
				break :blk zs.long.ptr[0..new_len];
			};

			mem.copyBackwards(u8, memory[move_idx..new_len], memory[i..old_len]);
			@memcpy(memory[i..move_idx], string);
			assert(zs.len() == new_len);
		}
		pub inline fn prepend(zs: *Self, allocator: Allocator, string: []const u8) Allocator.Error!void {
			return zs.insert(allocator, 0, string);
		}
		pub inline fn append(zs: *Self, allocator: Allocator, string: []const u8) Allocator.Error!void {
			return zs.insert(allocator, zs.len(), string);
		}


		pub fn remove(
			zs: *Self,
			allocator: Allocator,
			i: usizeMinusOne,
			length: usizeMinusOne,
		) void {
			const old_len = zs.len();
			const new_len = old_len - length;

			assert(i < old_len);

			const kind_ = zs.kind();

			const memory: []u8 = blk: {
				switch (kind_) {
					.local => break :blk zs.short.str[0..old_len+1],
					.remote => {},
					.heap => if (Self.fitsInShort(new_len)) {
						const str_ptr = &zs.short.str;
						const heap_memory = zs.long.ptr[0..zs.long.cap()];
						@memcpy(str_ptr[0..i], heap_memory[0..i]);
						@memcpy(str_ptr[i..new_len], heap_memory[i+length..old_len]);
						str_ptr[new_len] = 0;
						str_ptr[Self.max_short_size] = 0;
						allocator.free(heap_memory);
						return;
					},
				}
				zs.long.setLen(new_len);
				break :blk zs.long.ptr[0..old_len];
			};
			mem.copyForwards(u8, memory[i..memory.len-length], memory[i+length..memory.len]);

			if (kind_ == .heap) {
				const new_cap = Self.goodShrinkSize(new_len);
				if (new_cap < zs.long.cap()) {
					zs.heapResize(allocator, new_cap) catch {};
				}
			} else if (kind_ == .local) {
				assert(zs.short.len() == new_len);
			}
		}
		pub inline fn trimFront(zs: *Self, allocator: Allocator, length: usizeMinusOne) void {
			return zs.remove(allocator, 0, length);
		}
		pub inline fn trimBack(zs: *Self, allocator: Allocator, length: usizeMinusOne) void {
			return zs.remove(allocator, (zs.len() - length), length);
		}


		pub fn replace(
			zs: *Self,
			allocator: Allocator,
			i: usizeMinusOne,
			string: []const u8,
		) Allocator.Error!void {
			const old_len = zs.len();
			assert(i <= old_len);

			const new_len: usizeMinusOne = @intCast(@max(i+string.len, old_len));

			const memory: []u8 = blk: {
				switch (zs.kind()) {
					.local => if (Self.fitsInShort(new_len)) {
						const str_ptr = &zs.short.str;
						str_ptr[new_len] = 0;
						break :blk str_ptr[0..new_len];
					} else {
						const new_cap = Self.goodGrowSize(new_len);
						try zs.localToHeap(allocator, new_cap);
					},
					.remote => if (zs.long.cap() < new_len) return Allocator.Error.OutOfMemory,
					.heap => if (zs.long.cap() < new_len) {
						const new_cap = Self.goodGrowSize(new_len);
						try zs.heapResize(allocator, new_cap);
					},
				}
				zs.long.setLen(new_len);
				break :blk zs.long.ptr[0..new_len];
			};
			@memcpy(memory[i..][0..string.len], string);
		}


		/// Caller should make sure that `capacity >= zs.len()` for `.heap` strings, otherwise data will be lost.
		/// Returns actual capacity (`>= capacity`) after adjustment or an error if too little memory is available.
		pub fn setCapacity(zs: *Self, allocator: Allocator, capacity: usizeMinusOne) Allocator.Error!usizeMinusOne {
			switch (zs.kind()) {
				.local => if (Self.fitsInShort(capacity)) {
					return Self.max_short_size;
				} else {
					try zs.localToHeap(allocator, capacity);
				},
				.remote => if (zs.long.cap() < capacity) return Allocator.Error.OutOfMemory,
				.heap => if (Self.fitsInShort(capacity)) {
					const length = @min(zs.long.len(), Self.max_short_size);
					zs.heapToLocal(allocator, length);
					return Self.max_short_size;
				} else {
					try zs.heapResize(allocator, capacity);
					zs.long.setLen(@min(zs.long.len(), capacity));
				},
			}
			return zs.long.cap();
		}


		/// Although not necessary, it is safe to call `deinit()` on `zs` after this,
		/// as `toOwned()` empties the string. The caller owns the returned memory.
		pub fn toOwned(zs: *Self, allocator: Allocator) Allocator.Error![]u8 {
			const owned = blk: {
				const memory = switch (zs.kind()) {
					.local => zs.short.str[0..zs.short.len()],
					.remote => zs.long.ptr[0..zs.long.len()],
					.heap => {
						const mem_ptr = zs.long.ptr;
						const capacity = zs.long.cap();
						const length = zs.long.len();
						break :blk if (capacity == length)
							mem_ptr[0..length]
						else
							try allocator.realloc(mem_ptr[0..capacity], length);
					},
				};
				break :blk try allocator.dupe(u8, memory);
			};
			zs.* = Self.empty;
			return owned;
		}

		pub const Owned = union(Kind) {
			local: Local,
			remote: []u8,
			heap: List,

			pub const Local = struct {
				memory: [Self.max_short_size:0]u8,

				pub inline fn string(local: *Local) []u8 {
					return local.memory[0..mem.indexOfSentinel(u8, 0, &local.memory)];
				}
			};

			pub const List = std.ArrayListUnmanaged(u8);

			pub fn deinit(owned: *Owned, allocator: Allocator) void {
				switch (owned.*) {
					.local => {},
					.remote => |*remote| allocator.free(remote.*),
					.heap => |*heap| heap.deinit(allocator),
				}
				owned.* = undefined;
			}
		};
		pub fn toOwnedAdvanced(zs: *Self, allocator: Allocator) Allocator.Error!Owned {
			const owned: Owned = switch (zs.kind()) {
				.local => .{ .local = blk: {
					var local: Owned.Local = undefined;
					@memcpy(&local.memory, zs.short.str[0..Self.max_short_size]);
					break :blk local;
				}},
				.remote => .{ .remote = try allocator.dupe(u8, zs.long.ptr[0..zs.long.len()]) },
				.heap => .{ .heap = .{
					.items = zs.long.ptr[0..zs.long.len()],
					.capacity = zs.long.cap(),
				}},
			};
			zs.* = Self.empty;
			return owned;
		}


		pub inline fn fitsInShort(length: usizeMinusOne) bool {
			return (length <= Self.max_short_size);
		}

		pub const Integrity = enum {
			ok,
			missing_sentinel,
			points_to_null,
			capacity_overflow,
		};
		pub fn checkIntegrity(zs: *const Self) Integrity {
			if (zs.kind() == .local) {
				if (@as([*]const u8, &zs.short.str)[Self.max_short_size] != 0) return Self.logIntegrity(.missing_sentinel);
			} else {
				if (@intFromPtr(zs.long.ptr) == 0) return Self.logIntegrity(.points_to_null);
				if (zs.long.len() > zs.long.cap()) return Self.logIntegrity(.capacity_overflow);
			}
			return .ok;
		}
		fn logIntegrity(integrity: Integrity) Integrity {
			assert(integrity != .ok);
			const config_string = "ge=" ++ Self.boolToString(config.grow_eagerly)
				++ ",se=" ++ Self.boolToString(config.shrink_eagerly)
				++ ",ll=" ++ @tagName(config.log_level);
			@field(log, @tagName(config.log_level))
				("(config={{{s}}}): invalid state: '{s}'", .{ config_string, @tagName(integrity) });
			return integrity;
		}
		inline fn boolToString(value: bool) [:0]const u8 {
			return if (value) "true" else "false";
		}

		inline fn createLong(allocator: Allocator, capacity: usizeMinusOne) Allocator.Error!Self {
			return .{ .long = Self.Long.init(
				(try allocator.alloc(u8, capacity)).ptr,
				capacity,
				0,
				true,
			)};
		}

		inline fn goodGrowSize(length: usizeMinusOne) usizeMinusOne {
			return if (config.grow_eagerly)
				math.ceilPowerOfTwo(usizeMinusOne, length) catch Self.max_size
			else
				length;
		}
		inline fn goodShrinkSize(length: usizeMinusOne) usizeMinusOne {
			return if (config.shrink_eagerly)
				length
			else
				math.ceilPowerOfTwo(usizeMinusOne, length) catch Self.max_size;
		}

		inline fn localToHeap(zs: *Self, allocator: Allocator, capacity: usizeMinusOne) Allocator.Error!void {
			assert(zs.kind() == .local);
			var new_zs = try Self.createLong(allocator, capacity);
			const length = zs.short.len();
			new_zs.long.setLen(length);
			@memcpy(new_zs.long.ptr[0..length], zs.short.str[0..length]);
			zs.* = new_zs;
		}
		inline fn heapToLocal(zs: *Self, allocator: Allocator, length: usizeMinusOne) void {
			assert(zs.kind() == .heap);
			const str_ptr = &zs.short.str;
			const heap_memory = zs.long.ptr[0..zs.long.cap()];
			@memcpy(str_ptr[0..length], heap_memory[0..length]);
			str_ptr[length] = 0;
			str_ptr[Self.max_short_size] = 0;
			allocator.free(heap_memory);
		}
		inline fn heapResize(zs: *Self, allocator: Allocator, capacity: usizeMinusOne) Allocator.Error!void {
			assert(zs.kind() == .heap);
			zs.long.ptr = (try allocator.realloc(zs.long.ptr[0..zs.long.cap()], capacity)).ptr;
			zs.long.setCap(capacity);
		}


		// ================================= Tests =================================

		const TestConfig = struct {
			sizingFn: ?fn (length: usizeMinusOne) callconv(.Inline) usizeMinusOne,
		};
		fn Test(comptime test_config: TestConfig) type {
			if (!builtin.is_test) {
				@compileError("can only be used in tests");
			}
			return struct {
				zs: *const Self,

				pub fn init(zs: *Self) @This() {
					return .{ .zs = zs };
				}
				pub fn run(
					t: *const @This(),
					expected_capacity: ?usizeMinusOne,
					expected_string: []const u8,
					expected_kind: Self.Kind,
				) !void {
					try testing.expect(t.zs.checkIntegrity() == .ok);
					try testing.expect(t.zs.kind() == expected_kind);
					try testing.expect(t.zs.len() == expected_string.len);
					if (expected_capacity) |capacity| {
						try testing.expect(t.zs.cap() == capacity);
					} else if (test_config.sizingFn) |sizingFn| {
						if (expected_kind == .heap)
							try testing.expect(t.zs.long.cap() == sizingFn(t.zs.long.len()));
					}
					try testing.expectEqualStrings(expected_string, t.zs.raw());
				}
			};
		}

		test "Short.len" {
			var zs = Self.empty;
			try testing.expect(zs.short.len() == 0);

			@memcpy(zs.short.str[0..2], "ab");
			try testing.expect(zs.short.len() == 2);

			@memcpy(zs.short.str[2..5], "cde");
			try testing.expect(zs.short.len() == 5);

			@memset(zs.short.str[0..Self.max_short_size], 'x');
			try testing.expect(zs.short.len() == Self.max_short_size);

			try testing.expect(zs.checkIntegrity() == .ok);
		}

		test kind {
			const local = Self.empty;
			const remote = Self{ .long = Self.Long.init(undefined, 128, 64, false) };
			const heap = Self{ .long = Self.Long.init(undefined, 128, 64, true) };

			try testing.expect(local.kind() == .local);
			try testing.expect(remote.kind() == .remote);
			try testing.expect(heap.kind() == .heap);
		}

		test checkIntegrity {
			const local_valid = Self.empty;
			try testing.expect(local_valid.checkIntegrity() == .ok);

			const remote_valid = Self{ .long = Self.Long.init(@ptrFromInt(0xDEADBEEF), 128, 64, false) };
			try testing.expect(remote_valid.checkIntegrity() == .ok);

			const heap_valid = Self{ .long = Self.Long.init(@ptrFromInt(0xDEADBEEF), 128, 64, true) };
			try testing.expect(heap_valid.checkIntegrity() == .ok);

			// Change this to '.warn' or lower if any of the expects below fail.
			testing.log_level = .err;

			var local_no_sentinel = Self.empty;
			@memset(local_no_sentinel.short.str[0..Self.max_short_size], 0xAA);
			local_no_sentinel.short.str[Self.max_short_size] = 0b0111_1111;
			try testing.expect(local_no_sentinel.kind() == .local);
			try testing.expect(local_no_sentinel.checkIntegrity() == .missing_sentinel);

			var long_points_to_null = Self.empty;
			long_points_to_null.long.len_plus_tag.flag = @intFromEnum(Tag.long);
			try testing.expect(long_points_to_null.checkIntegrity() == .points_to_null);

			const long_capacity_overflow = Self{ .long = .{
				.ptr = @ptrFromInt(0xDEADBEEF),
				.cap_plus_is_owner = .{ .size = 128, .flag = @intFromBool(true) },
				.len_plus_tag = .{ .size = 129, .flag = @intFromEnum(Self.Tag.long) },
			}};
			try testing.expect(long_capacity_overflow.checkIntegrity() == .capacity_overflow);
		}

		test clone {
			const CloneTest = struct {
				allocator: Allocator,
				zs: *const Self,

				const InnerTest = Self.Test(.{ .sizingFn = null });

				pub fn init(allocator: Allocator, zs: *const Self) @This() {
					return .{
						.allocator = allocator,
						.zs = zs,
					};
				}
				pub fn run(
					t: *const @This(),
					expected_clone_kind: Kind,
					options: CloneOptions,
				) !void {
					var cloned = try t.zs.clone(t.allocator, options);
					defer cloned.deinit(t.allocator);

					try testing.expect(t.zs.checkIntegrity() == .ok);

					const clone_test = InnerTest.init(&cloned);
					const expected_capacity = if (expected_clone_kind == .heap)
						if (options.truncate) t.zs.len() else t.zs.cap()
					else
						null;
					try clone_test.run(expected_capacity, t.zs.raw(), expected_clone_kind);
				}
			};

			const allocator = testing.allocator;

			const foo = "foo";

			var local = try Self.fromString(allocator, foo);
			defer local.deinit(allocator);

			const local_test = CloneTest.init(allocator, &local);

			try testing.expect(local.kind() == .local);
			try local_test.run(.local, .{});

			var buf: [2*max_short_size]u8 = undefined;
			@memcpy(buf[0..foo.len], foo);
			var remote = Self.initBuffer(&buf, foo.len);
			defer remote.deinit(undefined);

			const remote_test = CloneTest.init(allocator, &remote);

			try testing.expect(remote.kind() == .remote);
			try remote_test.run(.remote, .{ .copy_remotes = false });
			try remote_test.run(.local, .{ .copy_remotes = true });

			@memset(remote.long.ptr[remote.long.len()..][0..Self.max_short_size], 'x');
			remote.long.setLen(remote.long.len() + Self.max_short_size);
			try remote_test.run(.heap, .{ .copy_remotes = true });


			var heap = try Self.initCapacity(allocator, 2*Self.max_short_size);
			defer heap.deinit(allocator);
			@memset(heap.long.ptr[0..Self.max_short_size+1], 'x');
			heap.long.setLen(Self.max_short_size+1);

			const heap_test = CloneTest.init(allocator, &heap);

			try testing.expect(heap.kind() == .heap);
			try heap_test.run(.heap, .{});
		}

		test insert {
			const allocator = testing.allocator;

			const InsertTest = Self.Test(.{ .sizingFn = Self.goodGrowSize });

			const foo = "foo";
			const bar = "bar";
			const baz = "baz";
			const literal = &[_]u8{'x'}**Self.max_short_size;

			var zs = Self.empty;
			defer zs.deinit(allocator);

			const zs_test = InsertTest.init(&zs);

			try zs.append(allocator, foo);
			try zs_test.run(null, foo, .local);

			try zs.prepend(allocator, bar);
			try zs_test.run(null, bar ++ foo, .local);

			try zs.insert(allocator, bar.len, baz);
			try zs_test.run(null, bar ++ baz ++ foo, .local);

			try zs.append(allocator, literal);
			try zs_test.run(null, bar ++ baz ++ foo ++ literal, .heap);

			try zs.prepend(allocator, literal);
			try zs_test.run(null, literal ++ bar ++ baz ++ foo ++ literal, .heap);

			try zs.insert(allocator, literal.len + bar.len, literal);
			try zs_test.run(null, literal ++ bar ++ literal ++ baz ++ foo ++ literal, .heap);


			var buf: [16]u8 = undefined;
			@memcpy(buf[0..foo.len], foo);
			var remote = Self.initBuffer(&buf, foo.len);
			defer remote.deinit(allocator);

			const remote_test = InsertTest.init(&remote);

			try remote.append(allocator, bar);
			try remote_test.run(buf.len, foo ++ bar, .remote);

			const err = remote.prepend(allocator, &[_]u8{'x'}**buf.len);
			try testing.expectError(Allocator.Error.OutOfMemory, err);
			try remote_test.run(buf.len, foo ++ bar, .remote);
		}

		test remove {
			const allocator = testing.allocator;

			const RemoveTest = Self.Test(.{ .sizingFn = Self.goodShrinkSize });

			const foo = "foo";
			const bar = "bar";
			const baz = "baz";
			const literal = &[_]u8{'x'}**Self.max_short_size;

			var zs = try Self.fromString(allocator, foo ++ bar ++ literal ++ baz);
			defer zs.deinit(allocator);
			try testing.expect(zs.kind() == .heap);

			const zs_test = RemoveTest.init(&zs);

			zs.trimFront(allocator, foo.len);
			try zs_test.run(null, bar ++ literal ++ baz, .heap);

			zs.remove(allocator, bar.len, literal.len);
			try zs_test.run(null, bar ++ baz, .local);

			zs.trimBack(allocator, baz.len);
			try zs_test.run(null, bar, .local);


			var buf: [16]u8 = undefined;
			@memcpy(buf[0..foo.len+bar.len+baz.len], foo ++ bar ++ baz);
			var remote = Self.initBuffer(&buf, foo.len+bar.len+baz.len);
			defer remote.deinit(allocator);

			const remote_test = RemoveTest.init(&remote);

			remote.remove(allocator, foo.len, bar.len);
			try remote_test.run(buf.len, foo ++ baz, .remote);

			remote.trimFront(allocator, foo.len);
			try remote_test.run(buf.len, baz, .remote);

			remote.trimBack(allocator, baz.len);
			try remote_test.run(buf.len, "", .remote);
		}

		test replace {
			const ReplaceTest = Self.Test(.{ .sizingFn = Self.goodGrowSize });

			const allocator = testing.allocator;

			const foo = "foo";
			const bar = "bar";
			const baz = "baz";
			const literal = &[_]u8{'x'}**Self.max_short_size;


			var zs = try Self.fromString(allocator, foo ++ bar);
			defer zs.deinit(allocator);

			const zs_test = ReplaceTest.init(&zs);

			try zs.replace(allocator, foo.len, foo);
			try zs_test.run(null, foo ++ foo, .local);

			try zs.replace(allocator, foo.len + foo.len, baz);
			try zs_test.run(null, foo ++ foo ++ baz, .local);

			try zs.replace(allocator, foo.len, literal);
			try zs_test.run(null, foo ++ literal, .heap);

			try zs.replace(allocator, foo.len, bar);
			try zs_test.run(null, foo ++ bar ++ literal[bar.len..], .heap);


			var buf: [16]u8 = undefined;
			@memcpy(buf[0..foo.len+bar.len], foo ++ bar);
			var remote = Self.initBuffer(&buf, foo.len+bar.len);
			defer remote.deinit(allocator);

			const remote_test = ReplaceTest.init(&remote);

			try remote.replace(allocator, foo.len, baz);
			try remote_test.run(buf.len, foo ++ baz, .remote);

			try remote.replace(allocator, foo.len+baz.len, bar);
			try remote_test.run(buf.len, foo ++ baz ++ bar, .remote);

			const err = remote.replace(allocator, foo.len, &[_]u8{'x'}**buf.len);
			try testing.expectError(Allocator.Error.OutOfMemory, err);
			try remote_test.run(buf.len, foo ++ baz ++ bar, .remote);
		}

		test setCapacity {
			const SetCapacityTest = Self.Test(.{ .sizingFn = null });

			const allocator = testing.allocator;

			const foo = "foo";
			try testing.expect(Self.fitsInShort(foo.len));

			// local/heap string
			var zs = try Self.fromString(allocator, foo);
			defer zs.deinit(allocator);

			const zs_test = SetCapacityTest.init(&zs);

			// capacity <= Self.max_short_size, local string
			_ = try zs.setCapacity(allocator, Self.max_short_size/2);
			try zs_test.run(null, foo, .local);

			// capacity > Self.max_short_size, local string
			_ = try zs.setCapacity(allocator, 2*Self.max_short_size);
			try zs_test.run(2*Self.max_short_size, foo, .heap);

			// capacity > Self.max_short_size, heap string
			_ = try zs.setCapacity(allocator, 4*Self.max_short_size);
			try zs_test.run(4*Self.max_short_size, foo, .heap);

			// capacity <= Self.max_short_size, heap string
			_ = try zs.setCapacity(allocator, Self.max_short_size/2);
			try zs_test.run(null, foo, .local);


			// heap string
			const literal = &[_]u8{'x'}**(4*Self.max_short_size);
			var heap = try Self.fromString(allocator, literal);
			defer heap.deinit(allocator);

			const heap_test = SetCapacityTest.init(&heap);

			// capacity < length
			const half_len = literal.len/2;
			_ = try heap.setCapacity(allocator, half_len);
			try heap_test.run(half_len, literal[0..half_len], .heap);

			// OOM
			var failing_allocator_instance = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 1 });
			const failing_allocator = failing_allocator_instance.allocator();
			var heap2 = try Self.fromString(failing_allocator, literal);
			defer heap2.deinit(failing_allocator);

			const heap2_test = SetCapacityTest.init(&heap2);

			const heap2_cap = heap2.cap();
			try testing.expectError(Allocator.Error.OutOfMemory, heap2.setCapacity(failing_allocator, 2*heap2_cap));
			try heap2_test.run(heap2_cap, literal, .heap);


			// remote string
			var buf: [16]u8 = undefined;
			@memcpy(buf[0..foo.len], foo);
			var remote = Self.initBuffer(&buf, foo.len);
			defer remote.deinit(allocator);

			const remote_test = SetCapacityTest.init(&remote);

			// capacity <= remote capacity
			_ = try remote.setCapacity(allocator, buf.len/2);
			try remote_test.run(buf.len, foo, .remote);

			// capacity > remote capacity
			try testing.expectError(Allocator.Error.OutOfMemory, remote.setCapacity(allocator, buf.len+1));
			try remote_test.run(buf.len, foo, .remote);
		}

		test toOwned {
			const allocator = testing.allocator;

			const foo = "foo";
			const literal = &[_]u8{'x'}**Self.max_short_size;


			var local = try Self.fromString(allocator, foo);
			defer local.deinit(allocator);
			try testing.expect(local.kind() == .local);

			const local_owned = try local.toOwned(allocator);
			defer allocator.free(local_owned);

			try testing.expectEqualDeep(Self.empty.any, local.any);
			try testing.expectEqualStrings(foo, local_owned);


			var heap = try Self.fromString(allocator, foo ++ literal);
			defer heap.deinit(allocator);
			try testing.expect(heap.kind() == .heap);

			const heap_owned = try heap.toOwned(allocator);
			defer allocator.free(heap_owned);

			try testing.expectEqualDeep(Self.empty.any, heap.any);
			try testing.expectEqualStrings(foo ++ literal, heap_owned);


			var buf: [16]u8 = undefined;
			@memcpy(buf[0..foo.len], foo);
			var remote = Self.initBuffer(&buf, foo.len);
			defer remote.deinit(allocator);

			const remote_owned = try remote.toOwned(allocator);
			defer allocator.free(remote_owned);

			try testing.expectEqualDeep(Self.empty.any, remote.any);
			try testing.expectEqualStrings(foo, remote_owned);
		}

		test toOwnedAdvanced {
			const allocator = testing.allocator;

			const foo = "foo";
			const literal = &[_]u8{'x'}**Self.max_short_size;


			var local = try Self.fromString(allocator, foo);
			defer local.deinit(allocator);
			try testing.expect(local.kind() == .local);

			var local_owned = try local.toOwnedAdvanced(allocator);
			defer local_owned.deinit(allocator);

			try testing.expect(local_owned == .local);
			try testing.expectEqualDeep(Self.empty.any, local.any);
			try testing.expectEqualStrings(foo[0..foo.len], local_owned.local.string());


			var heap = try Self.fromString(allocator, foo ++ literal);
			defer heap.deinit(allocator);
			try testing.expect(heap.kind() == .heap);

			var heap_owned = try heap.toOwnedAdvanced(allocator);
			defer heap_owned.deinit(allocator);

			try testing.expect(heap_owned == .heap);
			try testing.expectEqualDeep(Self.empty.any, heap.any);
			try testing.expectEqualStrings(foo ++ literal, heap_owned.heap.items);


			var buf: [16]u8 = undefined;
			@memcpy(buf[0..foo.len], foo);
			var remote = Self.initBuffer(&buf, foo.len);
			defer remote.deinit(allocator);

			var remote_owned = try remote.toOwnedAdvanced(allocator);
			defer remote_owned.deinit(allocator);

			try testing.expect(remote_owned == .remote);
			try testing.expectEqualDeep(Self.empty.any, remote.any);
			try testing.expectEqualStrings(foo, remote_owned.remote);
		}
	};
}


test {
	const testing_log_level: std.log.Level = .warn;

	const TestStringLazySizing = ZestyString(.{
		.grow_eagerly = true,
		.shrink_eagerly = false,
		.log_level = testing_log_level,
	});
	const TestStringAccurateSizing = ZestyString(.{
		.grow_eagerly = false,
		.shrink_eagerly = true,
		.log_level = testing_log_level,
	});
	comptime {
		testing.refAllDeclsRecursive(TestStringLazySizing);
		testing.refAllDeclsRecursive(TestStringAccurateSizing);
	}
}
