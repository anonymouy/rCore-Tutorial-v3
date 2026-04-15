# Zero-Copy TX 改动汇总

## 改动目标

消除用户态发送路径中"栈上构造帧 -> memcpy 到 slot"的拷贝，
改为直接在共享 TX slot 上就地构造以太网帧，实现全路径零拷贝。

---

## 文件 1: `user/src/bin/bypass_udp.rs`

### 改动 1: `build_udp_frame` -> `build_udp_frame_into`

**Before:**
```rust
fn build_udp_frame(
    src_mac: &[u8; 6],
    src_ip: &[u8; 4],
    src_port: u16,
    dst_ip: &[u8; 4],
    dst_port: u16,
    payload: &[u8],
) -> ([u8; 2048], usize) {
    // ... 在栈上的 [u8; 2048] 中构造帧 ...
    let mut buf = [0u8; 2048];
    // ... 填充 Ethernet/IP/UDP 头和 payload ...
    (buf, frame_len)
}
```

**After:**
```rust
fn build_udp_frame_into(
    buf: &mut [u8],          // <-- 接收外部 buffer，直接写入
    src_mac: &[u8; 6],
    src_ip: &[u8; 4],
    src_port: u16,
    dst_ip: &[u8; 4],
    dst_port: u16,
    payload: &[u8],
) -> usize {                 // <-- 只返回长度，不返回数组
    // ... 直接在 buf 上构造帧 ...
    frame_len
}
```

### 改动 2: 发包处消除 memcpy

**Before:**
```rust
let (frame, frame_len) = build_udp_frame(&mac, &ip, 2001, &dst_ip, 26099, payload);
// ...
let slot = (base as usize + tx_off + idx * slot_size as usize) as *mut u8;
ptr::write(slot, len_bytes[0]);
ptr::write(slot.add(1), len_bytes[1]);
ptr::copy_nonoverlapping(frame.as_ptr(), slot.add(2), frame_len);  // <-- 拷贝!
```

**After:**
```rust
let slot = (base as usize + tx_off + idx * slot_size as usize) as *mut u8;
// 直接在 slot+2 上构造帧，无拷贝
let slot_buf = core::slice::from_raw_parts_mut(slot.add(2), slot_size as usize - 2);
let frame_len = build_udp_frame_into(slot_buf, &mac, &ip, 2001, &dst_ip, 26099, payload);
// 写长度前缀
let len_bytes = (frame_len as u16).to_le_bytes();
ptr::write(slot, len_bytes[0]);
ptr::write(slot.add(1), len_bytes[1]);
```

---

## 文件 2: `user/src/bin/bench_bypass.rs`

### 改动 1: `build_udp_frame` -> `build_udp_frame_into`

与 bypass_udp.rs 相同，但 payload 参数改为 `payload_size: usize`（benchmark 不需要真实 payload 内容）。

**Before:**
```rust
fn build_udp_frame(..., payload: &[u8]) -> ([u8; 2048], usize)
```

**After:**
```rust
fn build_udp_frame_into(buf: &mut [u8], ..., payload_size: usize) -> usize
```

### 改动 2: `tx_enqueue` 拆分为 `tx_slot_acquire` + `tx_slot_commit`

**Before:** 一步完成（接收预构造的 frame，内部 memcpy）
```rust
unsafe fn tx_enqueue(
    hdr, base, tx_off, slot_size, ring_size,
    frame: &[u8],       // <-- 已构造好的帧
    frame_len: usize,
) -> bool {
    // ...
    ptr::copy_nonoverlapping(frame.as_ptr(), slot.add(2), frame_len);  // <-- 拷贝!
    // ...
}
```

**After:** 两步完成（调用方在 slot 上就地构造）
```rust
// 第一步：获取 slot 指针
unsafe fn tx_slot_acquire(
    hdr, base, tx_off, slot_size, ring_size,
) -> Option<(*mut u8, u32)> {
    // 检查环是否满，返回 slot 指针和当前 tx_head
}

// 调用方在 slot 上直接构造帧:
//   let slot_buf = slice::from_raw_parts_mut(slot.add(2), slot_size - 2);
//   let frame_len = build_udp_frame_into(slot_buf, ...);

// 第二步：提交（写长度前缀 + 推进 tx_head）
unsafe fn tx_slot_commit(
    hdr, slot, frame_len, tx_head,
) {
    // 写长度前缀，fence，推进 tx_head
}
```

### 改动 3: 三个 benchmark 函数签名变更

所有 benchmark 函数不再接收预构造的 `frame: &[u8]`，改为接收 `mac`/`ip`/`payload_size`，
内部使用 `tx_slot_acquire` + `build_udp_frame_into` + `tx_slot_commit` 三步操作。

| 函数 | Before 参数 | After 参数 |
|------|-----------|-----------|
| `bench_tx_throughput` | `frame: &[u8], frame_len` | `mac: &[u8;6], ip: &[u8;4], payload_size` |
| `bench_rtt_latency` | `frame: &[u8], frame_len` | `mac: &[u8;6], ip: &[u8;4], payload_size` |
| `bench_burst_enqueue` | `frame: &[u8], frame_len` | `mac: &[u8;6], ip: &[u8;4], payload_size` |

### 改动 4: main 中删除预构造帧

**Before:**
```rust
let payload_buf = [0xABu8; 1024];
let (frame, frame_len) =
    build_udp_frame(&mac, &ip, SRC_PORT, &DST_IP, DST_PORT, &payload_buf[..payload_size]);
bench_tx_throughput(hdr, base, tx_off, slot_size, ring_size, &frame, frame_len, count);
```

**After:**
```rust
// 不再预构造帧，直接传 mac/ip/payload_size
bench_tx_throughput(hdr, base, tx_off, slot_size, ring_size, &mac, &ip, payload_size, count);
```

---

## 效果

**改动前（有一次用户态拷贝）:**
```
用户栈 [u8; 2048]  --memcpy-->  TX slot  --DMA-->  网卡
                    ^^^^^^^^^
                    这次拷贝被消除
```

**改动后（全路径零拷贝）:**
```
TX slot (共享页)  <--就地构造--  用户程序
TX slot (共享页)  --DMA-->  网卡
```

数据从构造到发出，始终驻留在同一物理页帧上，没有任何拷贝。
