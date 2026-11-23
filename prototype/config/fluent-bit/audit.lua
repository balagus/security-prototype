-- Phase 4: normalization and lab alert rules for the log shipper (config/fluent-bit).
--
-- Every record leaves this filter as one flat JSON object with at least:
--   timestamp    ISO 8601 UTC, from the source record (not the time Fluent Bit read it)
--   source       pg-primary | pg-replica | maria-primary | maria-replica | openbao |
--                pg-sweeper | maria-sweeper | lease-reconciler (from the tag "<kind>.<source>")
--   engine       postgresql | mariadb | openbao | sweeper | backstop | reconciler
--   user         database account (OpenBao: the person, auth.metadata.username)
--   client_host  client address ("[local]" / "localhost" for the socket)
--   event        login | login_failed | logout | connection_received | authenticated |
--                audit | query | error | log (databases); request | response (OpenBao);
--                the sweeper action (start, terminated, killed, error, ...)
--   statement    the statement (pgAudit / server_audit / failed statement), when there is one
-- plus engine-specific fields, and "alert" + "alert_reason" when an alert rule matched.
--
-- Alert rules (lab form):
--   login_not_allowlisted  a successful database login by an account that is not on the
--                          allowlist below and is not a temp user (name starts with "v-")
--   superuser_login        any login or login attempt of the superuser account: PostgreSQL
--                          "postgres", MariaDB "root". One exception: the PostgreSQL image
--                          healthcheck (local socket AND application_name pg-healthcheck).
--   temp_user_denied       a temp user's statement refused by a privilege check
--                          (PostgreSQL SQLSTATE 42501, MariaDB access-denied error codes)
--   temp_user_write        a temp user's statement that tries to write or change anything,
--                          whatever the outcome (on a replica it is always refused)
--   openbao_request_failed an OpenBao response with an error (stand-in for "audit device
--                          failure", which cannot be seen in the audit log it breaks)
-- Revocation backstops (design 5.4, "Revocation depends on the replica being reachable"):
--   replica_startup_purge  maria-replica dropped one or more v- users at startup (init_file,
--                          before it accepted connections): users that were left on the replica
--                          (revocation pending while it was down, or still-valid leases)
--   replica_expiry_backstop maria-replica's event dropped v- users older than max_ttl + margin:
--                          OpenBao failed to revoke them
--   irrevocable_lease_found the lease reconciler found an irrevocable database lease (OpenBao
--                          gave up after 6 failed revocation attempts)
--   revocation_retried_by_reconciler the reconciler re-revoked a pending or irrevocable lease
--                          (any outcome; outcome=failed means the database is still unreachable)
-- PostgreSQL replica deny list (config/postgres/pg-deny-watcher.sh, source pg-replica, engine
-- backstop, target_engine postgresql):
--   pg_replica_deny_applied  pg-replica now refuses the temp role(s) of a lease whose revocation
--                          is pending or irrevocable (primary unreachable); users = the roles
--                          matched, terminated = sessions ended, over_deny=1 = more than one role
--   pg_deny_descriptor_rejected a file in the descriptor volume failed validation (only the
--                          reconciler can write there: a bug or a compromised reconciler)
--   pg_deny_watcher_failed the watcher exited and was restarted, its supervisor was stopped, the
--                          descriptor directory is unreadable, or a rewrite/reload failed
--   pg_server_process_crashed the postmaster saw a child die abnormally and restarted every
--                          session (also what killing the watcher's supervisor with SIGKILL does)

-- Accounts allowed to log in, per engine (temp users "v-..." are always allowed).
local ALLOW = {
  postgresql = {
    app1_runtime = true, app1_migrator = true, bao_admin = true,
    session_sweeper = true, replicator = true,
    postgres = true,          -- allowed, but every login raises superuser_login
  },
  mariadb = {
    app1_runtime = true, app1_migrator = true, bao_admin = true,
    session_sweeper = true, replicator = true,
    bao_replica_admin = true, -- OpenBao's local account on maria-replica (temp users live there)
    healthcheck = true,       -- the image's local healthcheck account (not audited, see compose)
    root = true,              -- allowed, but every login raises superuser_login
  },
}
local SUPERUSER = { postgresql = "postgres", mariadb = "root" }

-- MariaDB error codes of privilege refusals.
local MARIA_DENIED = {
  ["1044"] = true,  -- ER_DBACCESS_DENIED_ERROR
  ["1142"] = true,  -- ER_TABLEACCESS_DENIED_ERROR
  ["1143"] = true,  -- ER_COLUMNACCESS_DENIED_ERROR
  ["1227"] = true,  -- ER_SPECIFIC_ACCESS_DENIED_ERROR
  ["1370"] = true,  -- ER_PROCACCESS_DENIED_ERROR
  ["1290"] = true,  -- ER_OPTION_PREVENTS_STATEMENT (--read-only)
}

local WRITE_WORDS = {
  insert = true, update = true, delete = true, merge = true, replace = true, truncate = true,
  copy = true, create = true, alter = true, drop = true, grant = true, revoke = true,
  rename = true, load = true, call = true, ["do"] = true, lock = true, vacuum = true,
  reindex = true, cluster = true, comment = true, security = true, refresh = true,
  import = true, handler = true, install = true, uninstall = true,
}

local function is_temp(u) return type(u) == "string" and u:sub(1, 2) == "v-" end

local function first_word(stmt)
  if type(stmt) ~= "string" then return nil end
  -- skip leading blanks, comments of the form /* */ and opening parentheses
  local s = stmt:gsub("^%s+", "")
  while s:sub(1, 2) == "/*" do
    local e = s:find("*/", 3, true)
    if not e then break end
    s = s:sub(e + 2):gsub("^%s+", "")
  end
  s = s:gsub("^[%(%s]+", "")
  local w = s:match("^([%a_]+)")
  if w then return w:lower() end
  return nil
end

local function is_write(stmt)
  local w = first_word(stmt)
  if not w then return false end
  if WRITE_WORDS[w] then return true end
  -- SELECT ... INTO OUTFILE / DUMPFILE, SELECT ... FOR UPDATE
  if w == "select" or w == "with" then
    local l = stmt:lower()
    if l:find("into%s+outfile") or l:find("into%s+dumpfile") or l:find("for%s+update") then return true end
  end
  return false
end

local function set_alert(out, name, reason)
  if out.alert == nil then
    out.alert = name
    out.alert_reason = reason
  end
end

-- Login rules shared by both database engines.
local function login_rules(out, engine)
  local u = out.user
  if type(u) ~= "string" or u == "" then return end
  if out.event == "login" and not ALLOW[engine][u] and not is_temp(u) then
    set_alert(out, "login_not_allowlisted", engine .. " login by an account that is not on the allowlist")
  end
  if (out.event == "login" or out.event == "login_failed") and u == SUPERUSER[engine] then
    -- The image healthcheck and pg-replica's deny-list watcher (local socket only; the watcher
    -- logs every action itself).
    local healthcheck = engine == "postgresql" and out.client_host == "[local]"
      and (out.application_name == "pg-healthcheck" or out.application_name == "pg-deny-watcher")
    if not healthcheck then
      set_alert(out, "superuser_login", engine .. " superuser account " .. u .. " " .. out.event)
    end
  end
end

local function temp_statement_rules(out, denied)
  if not is_temp(out.user) then return end
  if out.statement ~= nil and is_write(out.statement) then
    set_alert(out, "temp_user_write", "temporary user tried to write or change something")
  elseif denied then
    set_alert(out, "temp_user_denied", "temporary user statement refused by a privilege check")
  end
end

-- pgAudit message: AUDIT: <type>,<stmt id>,<substmt id>,<class>,<command>,<obj type>,<obj name>,<statement>,<parameter>
-- The statement is CSV-quoted when it contains a comma, a quote or a line break.
local function parse_pgaudit(msg)
  local s = msg:sub(8)
  local f = {}
  local pos = 1
  for i = 1, 7 do
    local c = s:find(",", pos, true)
    if not c then return nil end
    f[i] = s:sub(pos, c - 1)
    pos = c + 1
  end
  local rest = s:sub(pos)
  local stmt
  if rest:sub(1, 1) == '"' then
    local buf = {}
    local i = 2
    local n = #rest
    while i <= n do
      local ch = rest:sub(i, i)
      if ch == '"' then
        if rest:sub(i + 1, i + 1) == '"' then
          buf[#buf + 1] = '"'
          i = i + 2
        else
          break
        end
      else
        buf[#buf + 1] = ch
        i = i + 1
      end
    end
    stmt = table.concat(buf)
  else
    local last = rest:match(".*(),")
    if last then stmt = rest:sub(1, last - 1) else stmt = rest end
  end
  return { audit_type = f[1], statement_id = f[2], substatement_id = f[3], class = f[4],
           command = f[5], object_type = f[6], object_name = f[7] }, stmt
end

local function pg_time(ts)
  if type(ts) ~= "string" then return nil end
  local d, t = ts:match("^(%d+%-%d+%-%d+) (%d+:%d+:%d+[%.%d]*)")
  if d then return d .. "T" .. t .. "Z" end
  return ts
end

local function normalize_pg(source, r)
  local msg = r["message"] or ""
  local out = {
    timestamp = pg_time(r["timestamp"]),
    source = source,
    engine = "postgresql",
    user = r["user"],
    client_host = r["remote_host"],
    database = r["dbname"],
    pid = r["pid"],
    session_id = r["session_id"],
    application_name = r["application_name"],
    severity = r["error_severity"],
    state_code = r["state_code"],
    backend_type = r["backend_type"],
  }
  if msg:sub(1, 7) == "AUDIT: " then
    local a, stmt = parse_pgaudit(msg)
    if a then
      out.event = "audit"
      out.audit_class = a.class
      out.audit_command = a.command
      out.audit_object = (a.object_name ~= "" and a.object_name) or nil
      out.statement = stmt
    else
      out.event = "audit"
      out.message = msg
    end
    if is_temp(out.user) and a and (a.class == "WRITE" or a.class == "DDL" or a.class == "ROLE") then
      set_alert(out, "temp_user_write", "temporary user ran a " .. a.class .. " statement")
    end
  elseif msg:find("^connection authorized: ") or msg:find("^replication connection authorized: ") then
    out.event = "login"
    out.user = out.user or msg:match("user=(%S+)")
    out.application_name = out.application_name or msg:match("application_name=(%S+)")
    out.message = msg
  elseif msg:find("^disconnection: ") then
    out.event = "logout"
    out.message = msg
  elseif msg:find("^connection authenticated: ") then
    out.event = "authenticated"
    out.message = msg
  elseif msg:find("^connection received: ") then
    out.event = "connection_received"
    out.client_host = out.client_host or msg:match("host=([^%s]+)")
  elseif out.severity == "FATAL" and (msg:find("password authentication failed", 1, true)
      or msg:find("pg_hba.conf rejects", 1, true) or msg:find("no pg_hba.conf entry", 1, true)
      or msg:find("^role \".*\" does not exist") or msg:find("is not permitted to log in", 1, true)
      or msg:find("too many connections for role", 1, true)) then
    out.event = "login_failed"
    out.user = out.user or msg:match('user "([^"]+)"')
    out.message = msg
    out.detail = r["detail"]
  elseif out.severity == "ERROR" then
    out.event = "error"
    out.message = msg
    out.statement = r["statement"]
  else
    out.event = "log"
    out.message = msg
    out.detail = r["detail"]
  end
  login_rules(out, "postgresql")
  -- The postmaster logs this (LOG) only for an ABNORMAL child exit, before it terminates every
  -- other session and reinitializes.
  if msg:find("^server process %(PID %d+%) ") and (msg:find("was terminated by", 1, true)
      or msg:find("exited with exit code", 1, true)) then
    set_alert(out, "pg_server_process_crashed", "a PostgreSQL child process died abnormally; the postmaster restarted every session")
  end
  if out.event == "error" then
    temp_statement_rules(out, out.state_code == "42501" or out.state_code == "25006")
  end
  return out
end

local function maria_time(ts)
  if type(ts) ~= "string" then return nil end
  local y, m, d, t = ts:match("^(%d%d%d%d)(%d%d)(%d%d) (%d+:%d+:%d+)")
  if y then return y .. "-" .. m .. "-" .. d .. "T" .. t .. "Z" end
  return ts
end

-- server_audit writes the statement in single quotes with \' \\ \n \r \t escapes.
local MARIA_ESC = { ["'"] = "'", ["\\"] = "\\", n = "\n", r = "\r", t = "\t" }
local function unquote_maria(obj)
  if type(obj) ~= "string" then return nil end
  if obj:sub(1, 1) == "'" and obj:sub(-1) == "'" and #obj >= 2 then
    local s = obj:sub(2, -2)
    return (s:gsub("\\(.)", function(c) return MARIA_ESC[c] or ("\\" .. c) end))
  end
  return obj
end

local function normalize_maria(source, r)
  local op = r["operation"] or ""
  local rc = r["retcode"] or ""
  local out = {
    timestamp = maria_time(r["ts"]),
    source = source,
    engine = "mariadb",
    user = r["username"],
    client_host = r["host"],
    database = (r["database"] ~= "" and r["database"]) or nil,
    connection_id = r["connid"],
    query_id = r["queryid"],
    operation = op,
    retcode = rc,
  }
  if op == "CONNECT" then
    if rc == "0" then out.event = "login" else out.event = "login_failed" end
  elseif op == "FAILED_CONNECT" then
    out.event = "login_failed"
  elseif op == "DISCONNECT" then
    out.event = "logout"
  elseif op == "CHANGEUSER" then
    out.event = "login"
  elseif op:sub(1, 5) == "QUERY" then
    out.event = "query"
    out.statement = unquote_maria(r["object"])
  else
    out.event = op:lower()
    out.object = r["object"]
  end
  login_rules(out, "mariadb")
  if out.event == "query" then
    temp_statement_rules(out, rc ~= "0" and MARIA_DENIED[rc] == true)
  end
  return out
end

local function normalize_bao(source, r)
  local auth = r["auth"] or {}
  local req = r["request"] or {}
  local resp = r["response"] or {}
  local meta = auth["metadata"] or {}
  local secret = resp["secret"] or {}
  local data = resp["data"] or {}
  local person = meta["username"] or auth["display_name"]
  local out = {
    timestamp = r["time"],
    source = source,
    engine = "openbao",
    event = r["type"],
    user = person,
    display_name = auth["display_name"],
    entity_id = auth["entity_id"],
    client_host = req["remote_address"],
    request_id = req["id"],
    operation = req["operation"],
    path = req["path"],
    mount_type = req["mount_type"],
    lease_id = secret["lease_id"],
    db_username = (type(data["username"]) == "string" and data["username"]) or nil,
    error = (r["error"] ~= nil and r["error"] ~= "" and r["error"]) or nil,
    statement = (req["operation"] or "") .. " " .. (req["path"] or ""),
  }
  if out.event == "response" and out.error then
    set_alert(out, "openbao_request_failed", "OpenBao returned an error: " .. tostring(out.error))
  end
  return out
end

local function normalize_sweeper(source, r)
  local line = r["log"] or ""
  local kv = {}
  for k, v in line:gmatch('([%w_]+)=("[^"]*")') do kv[k] = v:sub(2, -2) end
  for k, v in line:gmatch('([%w_]+)=([^%s"]+)') do if kv[k] == nil then kv[k] = v end end
  local out = {
    timestamp = line:match("^(%d+%-%d+%-%d+T%d+:%d+:%d+Z)"),
    source = source,
    engine = "sweeper",
    target_engine = kv["engine"],
    event = kv["action"],
    user = kv["role"] or kv["user"],
    client_host = kv["host"],
    session = kv["pid"] or kv["id"],
    reason = kv["reason"],
    detail = kv["detail"],
    statement = line,
  }
  return out
end

-- Revocation backstops: plain key=value lines
--   <time> engine=mariadb action=startup-purge|expiry-drop dropped=<n> users=<a,b> ...
--   <time> engine=openbao-reconciler action=<a> lease=<id> role=<role> outcome=<o> [detail="..."]
local function normalize_backstop(source, r, engine)
  local line = r["log"] or ""
  local kv = {}
  for k, v in line:gmatch('([%w_]+)=("[^"]*")') do kv[k] = v:sub(2, -2) end
  for k, v in line:gmatch('([%w_]+)=([^%s"]+)') do if kv[k] == nil then kv[k] = v end end
  local out = {
    timestamp = line:match("^(%d+%-%d+%-%d+T%d+:%d+:%d+[%.%d]*Z)"),
    source = source,
    engine = engine,
    target_engine = kv["engine"],
    event = kv["action"],
    dropped = tonumber(kv["dropped"]),
    users = kv["users"],
    lease_id = kv["lease"],
    role = kv["role"],
    outcome = kv["outcome"],
    detail = kv["detail"],
    -- PostgreSQL deny-list watcher fields
    descriptor = kv["descriptor"],
    issued = tonumber(kv["issued"]),
    matched = tonumber(kv["matched"]),
    terminated = tonumber(kv["terminated"]),
    over_deny = tonumber(kv["over_deny"]),
    entries = tonumber(kv["entries"]),
    reason = kv["reason"],
    pattern = kv["pattern"],
    receiver = kv["receiver"],
    pid = tonumber(kv["pid"]),
    statement = line,
  }
  if engine == "backstop" and out.target_engine == "postgresql" then
    if out.event == "deny-applied" then
      set_alert(out, "pg_replica_deny_applied", "pg-replica refuses " .. tostring(out.users) ..
        " (lease of role " .. tostring(out.role) .. " pending revocation; " .. tostring(out.terminated) ..
        " session(s) terminated" .. ((out.over_deny == 1) and "; more than one role matched" or "") .. ")")
    elseif out.event == "descriptor-rejected" then
      set_alert(out, "pg_deny_descriptor_rejected", "pg-replica rejected deny descriptor " ..
        tostring(out.descriptor) .. " (" .. tostring(out.reason) .. ")")
    elseif out.event == "watcher-restarted" or out.event == "supervisor-stopped" or out.event == "error"
        or out.event == "reload-failed" then
      set_alert(out, "pg_deny_watcher_failed", "pg-replica deny-list watcher: " .. tostring(out.event) ..
        " " .. tostring(out.reason or out.detail or ""))
    end
  elseif engine == "backstop" then
    if out.event == "startup-purge" and (out.dropped or 0) > 0 then
      set_alert(out, "replica_startup_purge", "maria-replica dropped " .. tostring(out.dropped) ..
        " temporary user(s) at startup, before accepting connections")
    elseif out.event == "expiry-drop" then
      set_alert(out, "replica_expiry_backstop", "maria-replica dropped " .. tostring(out.dropped) ..
        " temporary user(s) older than max_ttl + margin: OpenBao did not revoke them")
    end
  elseif engine == "reconciler" then
    if out.event == "irrevocable-found" then
      set_alert(out, "irrevocable_lease_found", "OpenBao lease is irrevocable: " .. tostring(out.lease_id))
    elseif out.event == "revoke-retried" or out.event == "revoke-irrevocable" then
      set_alert(out, "revocation_retried_by_reconciler", "the reconciler re-revoked " ..
        tostring(out.lease_id) .. " (outcome " .. tostring(out.outcome) .. ")")
    end
  end
  return out
end

-- Image healthchecks connect every 5 s (PostgreSQL: local socket as postgres with
-- application_name pg-healthcheck; MariaDB: the local "healthcheck" account). Their routine
-- connect/disconnect records are not shipped (about 100,000 lines a day per server); they stay
-- in the source logs. A FAILED healthcheck login, and anything else these sessions do, is
-- shipped.
local LOCAL_HOSTS = { localhost = true, ["127.0.0.1"] = true, ["::1"] = true }
local function is_healthcheck_noise(out)
  if out.engine == "postgresql" and out.client_host == "[local]" then
    if out.event == "connection_received" or out.event == "authenticated" then return true end
    if (out.event == "login" or out.event == "logout") and out.user == "postgres"
        and out.application_name == "pg-healthcheck" then return true end
  elseif out.engine == "mariadb" and out.user == "healthcheck" and LOCAL_HOSTS[out.client_host]
      and (out.event == "login" or out.event == "logout") and out.retcode == "0" then
    return true
  end
  return false
end

function normalize(tag, timestamp, record)
  local kind, source = tag:match("^([%w]+)%.(.+)$")
  local out
  if kind == "pg" then
    out = normalize_pg(source, record)
    if is_healthcheck_noise(out) then return -1, timestamp, record end
  elseif kind == "maria" then
    out = normalize_maria(source, record)
    if is_healthcheck_noise(out) then return -1, timestamp, record end
  elseif kind == "bao" then
    out = normalize_bao(source, record)
  elseif kind == "sweeper" then
    out = normalize_sweeper(source, record)
  elseif kind == "backstop" then
    out = normalize_backstop(source, record, "backstop")
  elseif kind == "reconciler" then
    out = normalize_backstop(source, record, "reconciler")
  else
    return 0, timestamp, record
  end
  return 2, timestamp, out
end
