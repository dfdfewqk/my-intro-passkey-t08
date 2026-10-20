-- Applied in Supabase on 2026-10-20. No passkeys deleted by this migration.
create or replace function public.t08_remove_owner_passkey(
 p_session_hash text,p_credential_id text)
returns jsonb language plpgsql set search_path=public,pg_temp as $$
declare
 n integer;
 old_name text;
 session_created timestamptz;
 session_credential text;
 sessions_revoked integer;
begin
 perform pg_advisory_xact_lock(8824004);
 select s.created_at,s.credential_id into session_created,session_credential
 from public.t08_login_sessions s
 where s.session_hash=p_session_hash and s.owner_id=1
  and s.revoked_at is null and s.expires_at>now();
 if session_created is null then raise exception 'session_expired_or_revoked';end if;
 if session_created<now()-interval '15 minutes' then raise exception 'recent_login_required';end if;
 select count(*) into n from public.t08_passkeys where owner_id=1;
 if n<=1 then raise exception 'last_passkey_protected';end if;
 select display_name into old_name from public.t08_passkeys where owner_id=1 and credential_id=p_credential_id;
 if old_name is null then raise exception 'credential_not_found';end if;
 update public.t08_login_sessions set revoked_at=now()
 where owner_id=1 and credential_id=p_credential_id and revoked_at is null;
 get diagnostics sessions_revoked=row_count;
 delete from public.t08_passkeys where owner_id=1 and credential_id=p_credential_id;
 insert into public.t08_key_events(event_type,credential_id_sha256,display_name)
 values('removed',encode(sha256(convert_to(p_credential_id,'UTF8')),'hex'),old_name);
 return jsonb_build_object('removed',true,'remaining',n-1,
  'sessionRevoked',session_credential=p_credential_id,
  'relatedSessionsRevoked',sessions_revoked);
end $$;
revoke all on function public.t08_remove_owner_passkey(text,text) from public,anon,authenticated;
grant execute on function public.t08_remove_owner_passkey(text,text) to service_role;
