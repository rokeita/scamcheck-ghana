-- ScamCheck Ghana — database schema (PostgreSQL / Supabase)
-- Matches the queries in webhook.py. Run once in the Supabase SQL editor.

-- People who message the bot (identified only by WhatsApp ID)
create table if not exists users (
    id            bigint generated always as identity primary key,
    whatsapp_id   text        not null unique,
    state         text        not null default 'idle'
                  check (state in ('idle', 'awaiting_number', 'awaiting_scam_type',
                                   'awaiting_description', 'awaiting_dispute')),
    state_data    jsonb       not null default '{}'::jsonb,
    blocked       boolean     not null default false,  -- set true to silence abusers
    reports_made  integer     not null default 0,
    created_at    timestamptz not null default now(),
    last_seen_at  timestamptz not null default now()
);

-- Every phone number that has been reported
create table if not exists phone_numbers (
    id                 bigint generated always as identity primary key,
    number             text        not null unique,   -- canonical, e.g. 233551234567
    display_number     text        not null,          -- local form, e.g. 0551234567
    risk_status        text        not null default 'clean'
                       check (risk_status in ('clean', 'watch', 'flagged')),
    report_count       integer     not null default 0,
    unique_reporters   integer     not null default 0,  -- 3+ = flagged
    first_reported_at  timestamptz,
    last_reported_at   timestamptz,
    created_at         timestamptz not null default now(),
    -- Expiry slice: fresh-review date + period behind it, lapse audit,
    -- and the counting cycle (a lapse starts a new cycle)
    fresh_review_date     timestamptz,
    fresh_review_interval interval,
    lapsed_at             timestamptz,
    flag_cycle            integer not null default 1
);

-- One row per report; one report per user per number
create table if not exists reports (
    id               bigint generated always as identity primary key,
    phone_number_id  bigint      not null references phone_numbers(id) on delete cascade,
    reporter_id      bigint      not null references users(id) on delete cascade,
    scam_type        text        not null
                     check (scam_type in ('fake_agent', 'wrong_number', 'prize_scam', 'other')),
    description      text,
    created_at       timestamptz not null default now(),
    cycle            integer not null default 1,
    unique (phone_number_id, reporter_id, cycle)
);

-- Owners of a flagged number asking for review
create table if not exists disputes (
    id               bigint generated always as identity primary key,
    phone_number_id  bigint      not null references phone_numbers(id) on delete cascade,
    contact          text        not null,   -- WhatsApp ID of the person disputing
    explanation      text        not null,
    status           text        not null default 'pending'
                     check (status in ('pending', 'upheld', 'rejected', 'inconclusive')),
    created_at       timestamptz not null default now(),
    reviewed_at      timestamptz
);

create index if not exists reports_phone_idx      on reports (phone_number_id);
create index if not exists reports_created_idx    on reports (created_at);
create index if not exists phone_numbers_risk_idx on phone_numbers (risk_status);
create index if not exists users_last_seen_idx    on users (last_seen_at);
create index if not exists disputes_status_idx    on disputes (status);
create index if not exists phone_numbers_expiry_idx on phone_numbers
    (risk_status, fresh_review_date) where fresh_review_date is not null;

-- Lock tables away from Supabase's public REST API. The webhook connects
-- directly with DATABASE_URL as the table owner, so it is unaffected.
alter table users         enable row level security;
alter table phone_numbers enable row level security;
alter table reports       enable row level security;
alter table disputes      enable row level security;
