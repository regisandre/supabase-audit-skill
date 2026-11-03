# Edge Functions

Make a table: function | `verify_jwt` (from `config.toml`, default true) | how the caller is
authenticated | authorization on ids from the request | notes. Then read each function.

## Auth models

- **`verify_jwt = true`**: the gateway only checks that the token is a valid JWT of the project.
  The anon key is one. The function must read the user (`auth.getUser(token)`) and check their
  rights on every id it acts on.
- **`verify_jwt = false`**: the function authenticates the caller itself. Accept only:
  - a webhook signature verified on the raw body with the provider's library or a constant-time
    compare, with a timestamp tolerance against replay;
  - a service-role or internal secret compared in constant time;
  - a device or terminal token that is issued server-side, bound to one scope (an event), expires,
    and is checked on every call.
- Read the shared auth helpers: a helper named "requireServiceRole" that only checks the
  `Authorization` header is present proves nothing.

## IDOR

Most functions use a service-role client, which bypasses RLS. Any `order_id`, `wallet_id`,
`event_id` or `user_id` taken from the body or the query string must be checked against the caller
before it is read or changed.

## Payments

Amounts, prices, currencies and fees come from the database, never from the client. Idempotency
keys on payment intents; webhook handlers idempotent on the event id.

- **Quantities too.** Server-side prices do not help if the client's quantity is trusted: a paid
  line plus a line of -100 on a cheap product sums to 0 and can reach a "free order" branch.
  Require a whole number of at least 1 on every line, in the endpoint and again in the database
  function that reserves stock.
- **Stock functions doing `stock - qty`**: a negative quantity raises stock, and a missing one
  (`SUM` of NULLs) sets it to NULL, which often means unlimited. Test both cases.
- When several entry points sell the same thing (website route, app Edge Function, terminal),
  diff their validation: one of them usually lags behind the others.
- A webhook that creates orders from PaymentIntent metadata must bind the connected account, the
  amount and the lines to the event; metadata is written by whoever created the intent.

## SSRF

Functions that fetch a URL from the request (scrapers, image moderation, resolvers) must restrict
scheme and host (allow-list), refuse private and link-local addresses after DNS resolution, cap
size and time, and not follow redirects blindly.

## OAuth

`state` generated server-side, bound to the user, single use, checked on callback. Redirect only to
an allow-listed URL. Tokens stored server-side, never returned to the client in full.

## Secrets and logs

No token, key, signature or full payload in `console.log`. Error responses carry a short code, not
the upstream error body.

- `return err(400, error.message)` after an RPC call hands the client constraint names, columns,
  echoed values and permission errors. Keep only what you raised yourself: SQLSTATE `P0001`
  (`RAISE EXCEPTION 'insufficient_funds'`) is yours and the apps may branch on it; map every
  other code to the endpoint's own code and log the full error. Grep for `.message` inside
  `json(`, `err(`, `new Response(` and `detail:` fields, not only one call shape.
- Payment provider errors: pass the message only for the provider's own error types (a card
  decline is written for the buyer), not for whatever else reached the catch block.

## CORS

`Access-Control-Allow-Origin: *` is fine with bearer tokens; never with cookie auth.

## Cost

- `pg_net` and cron-triggered functions: the cron log says "succeeded" when the HTTP call was only
  queued. Check `net._http_response` status codes.
- `net.http_post` stops waiting after 5 s by default. A batch function that runs longer keeps
  working, but every run is recorded as a timeout, and if the platform drops the invocation log
  when the client goes away, the function looks like it never ran. Match the timeout times to the
  cron schedules (`cron.job.schedule`), confirm the function's writes in the gateway logs, then
  pass `timeout_milliseconds` sized to the job (under the function's wall-clock limit) through
  `cron.alter_job`.
- Sort functions by calls x p50 from the logs; a function called by cron every minute that does
  nothing most of the time is cheaper to skip at the SQL side (check for work before calling).

## Storage endpoints

- A delete endpoint that checks only "signed in" lets any account delete any object: object paths
  are not secret, they are the path of every public asset URL. Derive the owning entity from the
  path (`<entity>/<id>/...`) and require edit rights on it, or restrict to the caller's own prefix.
- An upload endpoint that authorizes one folder pattern and accepts any other folder lets anyone
  write under another entity's prefix. Allow-list folders and check the owner of each.

## "Resolve or create" endpoints

An endpoint that finds a catalogue row by name or external id and creates it when missing, with a
service-role client, must check page rights like its siblings do. Otherwise any account creates
rows and, on a name match, overwrites existing ones (description, image, links).

## SSRF through a "helper" URL

A body field such as a profile URL passed to a scraper is a server-side fetch of a caller-chosen
URL. Validate the host with an anchored regex (`^https://(www\.)?provider\.com/...$`) and go
through the shared safe-fetch helper. Check that helper too: blocking IP literals without
resolving DNS lets a hostname pointing to a private address through.

## Fixes that need a second look

The first version of a fix is often bypassable. Seen in practice, each caught by reviewing the fix:

- **Ownership from a path, then a URL built from it**: `new URL()` normalises `%2e%2e` segments
  to `..`, so `users/<me>/a/%2e%2e/%2e%2e/%2e%2e/<other prefix>/x` passes a "my folder" check
  and deletes another key. Allow only plain segments (`[A-Za-z0-9._-]`, no leading dot) and
  check that the built request path equals the checked key.
- **Ownership from rows the attacker writes**: "a message of mine carries this file" proves
  nothing if senders write their own attachment JSON. Require that no one else's row carries
  it, or record the uploader server-side at upload time.
- **Deciding on a truncated list** (`limit(1000)` then `every(...)`): ask the database the exact
  question instead (`another sender exists? limit 1`).
- **A metadata binding that trusts the metadata's own numbers**: checking `amount >= sum(qty *
  unit_cents)` is void if `unit_cents` can be negative or a product belongs to another event.
  Validate each line (whole, non-negative, product of the event) before summing.

## Session tokens for devices

- Verification must fail closed: a revocation lookup that errors is a refusal, not a pass.
- Recheck the device's status on every call, so disabling it ends its sessions at once.
- Never embed the device's permanent credential in the session JWT: a JWT is only base64.
- A client-sent flag that relaxes rules (`source: offline`) must not be honoured on the live
  endpoint; offline batches have their own endpoint.

## RPCs that read `auth.uid()`

Called from an Edge Function on a service-role client, `auth.uid()` is NULL: the RPC refuses
(or worse, acts for nobody). Call it on a client built with the caller's JWT.

## Read paths that skip the write path's scope

When a write RPC checks scope (a token spendable only at its event, a resource of one tenant),
look for the read endpoints that serve the same object: a balance check, a preview, a "validate"
call. They often skip it. Move the rule into one function both paths call (server-only grant)
and test it table-driven.

## Idempotency

An idempotent replay must match the stored request (wallet, amount) or be refused; otherwise the
side effects run on the replay's body while the debit ran on the stored row.

## Public lookups

A public "validate this code" endpoint returns an allow-list of fields, never `select('*')`
(provider ids, usage counters).
