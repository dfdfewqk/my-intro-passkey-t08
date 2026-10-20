-- Card 5 redacted proof synchronization across Google Chrome profiles.
-- Applied to production by t08_card5_cross_profile_redacted_http_evidence.
-- The table deliberately does NOT store raw cookies, WebAuthn artifacts or private note text.
create table if not exists public.t08_card5_evidence(
 owner_id integer primary key references public.t08_accounts(id),
 observed_at timestamptz not null default now(),
 passkey_name text not null,
 own_http integer not null default 200 check(own_http=200),
 other_http integer not null default 403 check(other_http=403),
 deny_error text not null default 'other_account_forbidden'
 check(deny_error='other_account_forbidden'),
 after_http integer not null default 200 check(after_http=200),
 spoof_http integer not null default 200 check(spoof_http=200),
 spoof_owner_id integer not null,
 anonymous_http integer not null default 401 check(anonymous_http=401),
 before_count integer not null check(before_count between 0 and 10000),
 after_count integer not null check(after_count between 0 and 10000),
 check(before_count=after_count),
 check(spoof_owner_id=owner_id)
);
alter table public.t08_card5_evidence enable row level security;
revoke all on public.t08_card5_evidence from public,anon,authenticated;
grant select,insert,update on public.t08_card5_evidence to service_role;
