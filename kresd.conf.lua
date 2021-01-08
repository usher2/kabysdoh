-- Once you step into the waters of modifying in-flight DNS messages it seems
-- like crocodiles all the way down.
-- -- Mark Delany, https://mailarchive.ietf.org/arch/msg/doh/5h0vFMHEG95s4vlie5v7K85sxS8/
--
-- Thanks to awesome Lua manuals:
-- * http://www.lua.org/manual/5.1/manual.html (knot-resolver is built on top of LuaJIT with 5.1)
-- * http://luajit.org/extensions.html
-- * https://www.lua.org/pil/contents.html
-- * https://www.lua.org/gems/sample.pdf - Lua Performance Tips

local function cwd()
  local proc = io.popen('pwd')
  local d = proc:read('*l')
  proc:close()
  return d
end

-- https://mark.lindsey.name/2009/03/09/never-use-dns-ttl-of-zero-0/
-- https://00f.net/2011/11/17/how-long-does-a-dns-ttl-last/
local explanation_ttl = 0
local blockpage_ttl = 60
-- fd41:bb86:195d:b10c:bad:bad:10.10.34.34 from @darkk's ULA range, see https://ula.ungleich.ch/
local blockpage4 = '\10\10\34\34'
local blockpage6 = '\253\65\187\134\25\93\177\12\11\173\11\173\10\10\34\34'

local kd = require('kabydump')
local dump = kd.dodump('dump.lua')

-- kaby_action should be a separate module for the following reasons:
-- 1) `policy` action may drop unwanted RRs, but it can't create sub-query: it's in `finish` layer.
-- 2) Cloudflare does not depend on ECS and has TTL=300, it might be handled with cache + polling.
-- 3) Amazon Cloudfront uses ECS* and has TTL=60 for A RR.
-- *) Oops! Knot Resolver doesn't support ECS https://gitlab.nic.cz/knot/knot-resolver/-/issues/362
--
-- TODO: So, as we need subqueries...

-- TODO: take a look at `policy.evaluate` and decide if kaby_action() should be chain or non-chain.
-- The policy is very similar to `rule()` from kres_modules/renumber.lua; `req` is `kr_request*`.
local function kaby_action (state, req)
  if state == kres.FAIL then return state end
  -- local pkt = req:ensure_answer()
  -- if pkt == nil then return nil end
  local pkt = req.answer
  -- Only successful answers
  local records = pkt:section(kres.section.ANSWER)
  local ancount = #records
  if ancount == 0 then return state end
  -- Find renumber candidates
  local del = {}
  local rr4, del4, rr6, del6 = 0, 0, 0, 0 -- CNAME RRs matter!
  for i = 1, ancount do
    local rr = records[i]
    if rr.type == kres.type.A then
      rr4 = rr4 + 1
      if dump.bad_a(rr.rdata) then
        del[i] = true
        del4 = del4 + 1
      end
    elseif rr.type == kres.type.AAAA then
      rr6 = rr6 + 1
      if dump.bad_aaaa(rr.rdata) then
        del[i] = true
        del6 = del6 + 1
      end
    end
  end
  -- If not rewritten, chain action
  -- Mixture of A and AAAA is weird. Is it `ANY` reply or something else? Skipped for safety.
  if del4 + del6 == 0 or (rr4 > 0 and rr6 > 0) then return state end

  -- Replace section if renumbering
  local qname = pkt:qname()
  local qclass = pkt:qclass()
  local qtype = pkt:qtype()
  pkt:recycle()
  pkt:question(qname, qclass, qtype)

  if del4 + del6 < rr4 + rr6 then
    -- Some RRs are good to return.
    for i = 1, ancount do
      local rr = records[i]
      -- Strip signatures as rewritten data cannot be validated
      if rr.type ~= kres.type.RRSIG and not del[i] then
        pkt:put(rr.owner, rr.ttl, rr.class, rr.type, rr.rdata)
      end
    end
    pkt:begin(kres.section.ADDITIONAL)
    pkt:put('\11explanation\7invalid', explanation_ttl, qclass, kres.type.TXT, '\20Deleted unwanted RRs')
    return state
  end

  -- TODO: try to remap
  -- req:push('\3www\10cloudflare\3com', kres.type.A, kres.class.IN, extraFlags)
  -- return kres.CONSUME
  if rr4 > 0 then
    pkt:put(qname, blockpage_ttl, qclass, kres.type.A, blockpage4)
  elseif rr6 > 0 then
    pkt:put(qname, blockpage_ttl, qclass, kres.type.AAAA, blockpage6)
  end
  pkt:begin(kres.section.ADDITIONAL)
  pkt:put('\11explanation\7invalid', explanation_ttl, qclass, kres.type.TXT, '\36All RRs are unwanted, goto blockpage')
  return state
end

-- TODO: understand when the factory is called.
-- policy.add(function(req, query) return kaby_action end, true)
policy.add(policy.all(kaby_action), true)

net.listen(cwd()..'/control', nil, { kind = 'control' })

-- Why is rawset() called instead of plain `cache.current_storage = XXX`? Why is the latter broken?
rawset(cache, 'current_storage', 'lmdb://'..cwd()..'/cache')
cache.size = 100 * MB

-- -- Network interface configuration
net.listen('127.0.0.1', 27053, { kind = 'dns' })
net.listen('127.0.0.1', 27853, { kind = 'tls' })
net.listen('127.0.0.1', 27443, { kind = 'doh2' })

-- net.listen('::1', 53, { kind = 'dns', freebind = true })
-- net.listen('::1', 853, { kind = 'tls', freebind = true })
-- --net.listen('::1', 443, { kind = 'doh2' })
--
-- -- Load useful modules
-- modules = {
-- 	'hints > iterate',  -- Load /etc/hosts and allow custom root hints
-- 	'stats',            -- Track internal statistics
-- 	'predict',          -- Prefetch expiring/frequent records
-- }
