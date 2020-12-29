#!/usr/bin/lua5.1

local kd = require('kabydump')
local dump = kd.dodump('testdump.lua')

local good_a = {
  "\10\10\34\34",
  "\193\105\213\35",
  "\0\0\0\0\0\0\0\0\0\0\0\0\193\105\213\36",
  "\203\104\156\0",
  "\203\104\156\42",
}
local bad_a = {
  "\1\32\194\33",
  "\172\67\153\173",
  "\68\171\224\0",
  "\193\105\213\36",
  "\203\104\152\0",
  "\203\104\153\0",
  "\203\104\152\42",
}

for i = 1, #good_a do
  if dump.bad_a(good_a[i]) == false then print("OK") else print("FAIL") end
end
for i = 1, #bad_a do
  if dump.bad_a(bad_a[i]) == true then print("OK") else print("FAIL") end
end

local good_aaaa = {
  "\10\10\34\34",
  "\0\0\0\0\0\0\0\0\0\0\0\0\1\32\194\33",
  "\255\255\0\0\0\0\0\0\0\0\0\0\1\32\194\33",
  "\32\1\4\112\0\1\1\137\0\0\0\1\0\2\0\2",
  "\38\6\71\1\48\52\0\0\0\0\0\0\104\24\126\255",
  "\38\6\71\128\255\0\0\0\0\0\0\0\0\0\0\42",
  "\38\6\71\128\128\0\0\0\0\0\0\0\0\0\0\42",
  "\38\6\71\128\16\0\0\0\0\0\0\0\0\0\0\42",
}
local bad_aaaa = {
  "\32\1\4\112\0\1\1\137\0\0\0\1\0\2\0\3",
  "\38\6\71\0\48\52\0\0\0\0\0\0\104\24\126\47",
  "\38\6\71\0\48\52\0\0\0\0\0\0\104\24\126\255",
  "\38\6\71\128\15\0\0\0\0\0\0\0\0\0\0\42",
}

for i = 1, #good_aaaa do
  if dump.bad_aaaa(good_aaaa[i]) == false then print("OK") else print("FAIL") end
end
for i = 1, #bad_aaaa do
  if dump.bad_aaaa(bad_aaaa[i]) == true then print("OK") else print("FAIL") end
end

