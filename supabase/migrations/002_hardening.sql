-- CineTrack access hardening and helper indexes.
-- Run AFTER the initial CineTrack schema script already executed in Supabase.
-- This does not create users or expose invite records to browser clients.

create index if not exists cinetrack_items_updated_at_idx
  on public.cinetrack_items (updated_at desc);

-- Explicitly deny direct client access to invite records.
revoke all on table public.cinetrack_invites from anon, authenticated;
grant select on table public.cinetrack_members to authenticated;
grant select, insert, update, delete on table public.cinetrack_items to authenticated;

-- Reassert RLS. Anonymous Supabase sessions use the authenticated database role,
-- but they receive no access until their auth.uid() is present in cinetrack_members.
alter table public.cinetrack_members enable row level security;
alter table public.cinetrack_items enable row level security;
alter table public.cinetrack_invites enable row level security;

drop policy if exists "member_read_own" on public.cinetrack_members;
create policy "member_read_own"
on public.cinetrack_members
for select
to authenticated
using (user_id = (select auth.uid()));

drop policy if exists "members_access_items" on public.cinetrack_items;
create policy "members_access_items"
on public.cinetrack_items
for all
to authenticated
using (
  exists (
    select 1 from public.cinetrack_members m
    where m.user_id = (select auth.uid())
  )
)
with check (
  exists (
    select 1 from public.cinetrack_members m
    where m.user_id = (select auth.uid())
  )
);

-- No client policies or grants for cinetrack_invites.
-- The Edge Function uses the service-role key server-side only.
