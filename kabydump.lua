local bit = require('bit')

local function get_ffi_bitcmp()
  local ffi = require('ffi')
  return ffi.C.kr_bitcmp
end

local function lua_bitcmp(a, b, bitlen)
  if #a * 8 < bitlen or #b * 8 < bitlen then
    error({msg="lua_bitcmp needs full bit-string", a=a, b=b, bitlen=bitlen})
  end
  local ptr = 1
  while bitlen >= 8 do
    local a8 = string.byte(a, ptr)
    local b8 = string.byte(b, ptr)
    if a8 < b8 then
      return -1
    elseif a8 > b8 then
      return 1
    end
    ptr = ptr + 1
    bitlen = bitlen - 8
  end
  -- bitlen is in {0..7}
  local m8 = bit.band(bit.lshift(0xff, 8 - bitlen), 0xff)
  local am = bit.band(string.byte(a, ptr), m8)
  local bm = bit.band(string.byte(b, ptr), m8)
  if am < bm then
    return -1
  elseif am > bm then
    return 1
  else
    return 0
  end
end

local ok, bitcmp = pcall(get_ffi_bitcmp)
if not ok then
  print("WARN: no ffi.C.kr_bitcmp, slow lua_bitcmp is used")
  bitcmp = lua_bitcmp
end

local function dodump(fname)
  local dump = dofile(fname)
  -- TODO: it is nice to do *Subnet* validation here

  local function bad_a(addr)
    if #addr ~= 4 then return false end -- weird input
    local a, b, c, d = string.byte(addr, 1, 4)
    local u32 = a * 0x1000000 + b * 0x10000 + c * 0x100 + d
    if dump.ip[u32] == true then return true end -- bad <ip>
    local i32msb = bit.band(u32, dump.ipSubnetTrieMask)
    local netlist = dump.ipSubnet[i32msb]
    if netlist == nil then return false end -- no matching ipSubnet
    for i = 1, #netlist do
      local net = netlist[i]
      -- bit.bxor is used to keep ipSubnet as u32 values in dump.lua
      if bit.bxor(bit.band(u32, net[2]), net[1]) == 0 then
        return true -- ipSubnet match
      end
    end
    return false
  end

  local function bad_aaaa(addr)
    if #addr ~= 16 then return false end -- weird input
    if dump.ipv6[addr] == true then return true end -- bad <ipv6>
    local a, b, c, d = string.byte(addr, 1, 4)
    local u32 = a * 0x1000000 + b * 0x10000 + c * 0x100 + d
    local i32msb = bit.band(u32, dump.ipv6SubnetTrieMask)
    local netlist = dump.ipv6Subnet[i32msb]
    if netlist == nil then return false end -- no matching ipv6Subnet
    for i = 1, #netlist do
      local net = netlist[i]
      if bitcmp(addr, net[1], net[2]) == 0 then
        return true -- ipv6Subnet match
      end
    end
    return false
  end

  return { bad_a = bad_a, bad_aaaa = bad_aaaa }
end

return { dodump = dodump }
