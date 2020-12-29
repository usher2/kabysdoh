-- This is a (stripped) generated file. DO NOT EDIT! It is data for kabysdoh DoH policy.
local f = nil;
local ip = {}
f = function (t)
local x = true;
t[0x120c221]=x
t[0x120c243]=x
t[0x6812b0ba]=x
t[0x6812b0d5]=x
end
f(ip)
f = function (t)
local x = true;
t[0x6812b0dc]=x
t[0x6812b0ea]=x
t[0xac4399a9]=x
t[0xac4399aa]=x
end
f(ip)
f = function (t)
local x = true;
t[0xac4399ac]=x
t[0xac4399ad]=x
t[0xdf874b4c]=x
t[0xdfa540e4]=x
end
f(ip)
local ipv6 = {}
f = function (t)
local x = true;
t["\32\1\4\112\0\0\0\101\0\0\0\0\64\62\186\39"]=x
t["\32\1\4\112\0\1\1\137\0\0\0\1\0\2\0\3"]=x
t["\38\6\71\0\48\52\0\0\0\0\0\0\104\24\126\46"]=x
t["\38\6\71\0\48\52\0\0\0\0\0\0\104\24\126\47"]=x
end
f(ipv6)
f = function (t)
local x = true;
t["\38\6\71\0\48\52\0\0\0\0\0\0\104\24\126\55"]=x
t["\38\6\71\0\48\52\0\0\0\0\0\0\104\24\126\56"]=x
t["\44\15\249\48\0\0\0\4\0\0\0\0\0\0\1\8"]=x
t["\44\15\249\48\0\0\0\5\0\0\0\0\0\0\0\146"]=x
end
f(ipv6)
f = nil
local ipSubnetTrieMask = 0xffffe000;
local ipSubnet = {
[0x44abe000] = {
 { 0x44abe000, 0xffffe000 },
},
[0x67f6c000] = {
 { 0x67f6c800, 0xfffffc00 },
},
[-0x4d10c000] = {
 { 0xb2ef5800, 0xfffff800 },
},
[-0x3e964000] = {
 { 0xc169d524, 0xfffffffc },
},
[-0x34978000] = {
 { 0xcb688000, 0xfffff000 },
 { 0xcb689000, 0xfffff800 },
 { 0xcb689800, 0xfffffc00 },
},
};
local ipv6SubnetTrieMask = 0xffffffff;
local ipv6Subnet = {
[0x26064700] = {
 { "\38\6\71\0\0\0\0\0\0\0\0\0\0\0\0\0", 32 },
},
[0x26064780] = {
 { "\38\6\71\128\0\0\0\0\0\0\0\0\0\0\0\0", 36 },
},
};
return { ip = ip, ipSubnet = ipSubnet, ipSubnetTrieMask = ipSubnetTrieMask, ipv6 = ipv6, ipv6Subnet = ipv6Subnet, ipv6SubnetTrieMask = ipv6SubnetTrieMask };
-- EOF
