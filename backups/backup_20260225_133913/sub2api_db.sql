--
-- PostgreSQL database dump
--

\restrict dcY5lihiQ45wmClxbFokv0KIPaSTantWz3k0LIraCLa1hemSIDtufmJcosJD3PM

-- Dumped from database version 18.2
-- Dumped by pg_dump version 18.2

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: pg_trgm; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA public;


--
-- Name: EXTENSION pg_trgm; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION pg_trgm IS 'text similarity measurement and index searching based on trigrams';


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: account_groups; Type: TABLE; Schema: public; Owner: sub2api
--

CREATE TABLE public.account_groups (
    account_id bigint NOT NULL,
    group_id bigint NOT NULL,
    priority integer DEFAULT 50 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.account_groups OWNER TO sub2api;

--
-- Name: accounts; Type: TABLE; Schema: public; Owner: sub2api
--

CREATE TABLE public.accounts (
    id bigint NOT NULL,
    name character varying(100) NOT NULL,
    platform character varying(50) NOT NULL,
    type character varying(20) NOT NULL,
    credentials jsonb DEFAULT '{}'::jsonb NOT NULL,
    extra jsonb DEFAULT '{}'::jsonb NOT NULL,
    proxy_id bigint,
    concurrency integer DEFAULT 3 NOT NULL,
    priority integer DEFAULT 50 NOT NULL,
    status character varying(20) DEFAULT 'active'::character varying NOT NULL,
    error_message text,
    last_used_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone,
    schedulable boolean DEFAULT true NOT NULL,
    rate_limited_at timestamp with time zone,
    rate_limit_reset_at timestamp with time zone,
    overload_until timestamp with time zone,
    session_window_start timestamp with time zone,
    session_window_end timestamp with time zone,
    session_window_status character varying(20),
    temp_unschedulable_until timestamp with time zone,
    temp_unschedulable_reason text,
    notes text,
    expires_at timestamp with time zone,
    auto_pause_on_expired boolean DEFAULT true NOT NULL,
    rate_multiplier numeric(10,4) DEFAULT 1.0 NOT NULL
);


ALTER TABLE public.accounts OWNER TO sub2api;

--
-- Name: COLUMN accounts.temp_unschedulable_until; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON COLUMN public.accounts.temp_unschedulable_until IS '临时不可调度状态解除时间，当触发临时不可调度规则时设置（基于错误码或错误描述关键词）';


--
-- Name: COLUMN accounts.temp_unschedulable_reason; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON COLUMN public.accounts.temp_unschedulable_reason IS '临时不可调度原因，记录触发临时不可调度的具体原因（用于排障和审计）';


--
-- Name: COLUMN accounts.notes; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON COLUMN public.accounts.notes IS 'Admin-only notes for account';


--
-- Name: COLUMN accounts.expires_at; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON COLUMN public.accounts.expires_at IS 'Account expiration time (NULL means no expiration).';


--
-- Name: COLUMN accounts.auto_pause_on_expired; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON COLUMN public.accounts.auto_pause_on_expired IS 'Auto pause scheduling when account expires.';


--
-- Name: accounts_id_seq; Type: SEQUENCE; Schema: public; Owner: sub2api
--

CREATE SEQUENCE public.accounts_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.accounts_id_seq OWNER TO sub2api;

--
-- Name: accounts_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sub2api
--

ALTER SEQUENCE public.accounts_id_seq OWNED BY public.accounts.id;


--
-- Name: announcement_reads; Type: TABLE; Schema: public; Owner: sub2api
--

CREATE TABLE public.announcement_reads (
    id bigint NOT NULL,
    announcement_id bigint NOT NULL,
    user_id bigint NOT NULL,
    read_at timestamp with time zone DEFAULT now() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.announcement_reads OWNER TO sub2api;

--
-- Name: TABLE announcement_reads; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON TABLE public.announcement_reads IS '公告已读记录';


--
-- Name: COLUMN announcement_reads.read_at; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON COLUMN public.announcement_reads.read_at IS '用户首次已读时间';


--
-- Name: announcement_reads_id_seq; Type: SEQUENCE; Schema: public; Owner: sub2api
--

CREATE SEQUENCE public.announcement_reads_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.announcement_reads_id_seq OWNER TO sub2api;

--
-- Name: announcement_reads_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sub2api
--

ALTER SEQUENCE public.announcement_reads_id_seq OWNED BY public.announcement_reads.id;


--
-- Name: announcements; Type: TABLE; Schema: public; Owner: sub2api
--

CREATE TABLE public.announcements (
    id bigint NOT NULL,
    title character varying(200) NOT NULL,
    content text NOT NULL,
    status character varying(20) DEFAULT 'draft'::character varying NOT NULL,
    targeting jsonb DEFAULT '{}'::jsonb NOT NULL,
    starts_at timestamp with time zone,
    ends_at timestamp with time zone,
    created_by bigint,
    updated_by bigint,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.announcements OWNER TO sub2api;

--
-- Name: TABLE announcements; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON TABLE public.announcements IS '系统公告';


--
-- Name: COLUMN announcements.status; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON COLUMN public.announcements.status IS '状态: draft, active, archived';


--
-- Name: COLUMN announcements.targeting; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON COLUMN public.announcements.targeting IS '展示条件（JSON 规则）';


--
-- Name: COLUMN announcements.starts_at; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON COLUMN public.announcements.starts_at IS '开始展示时间（为空表示立即生效）';


--
-- Name: COLUMN announcements.ends_at; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON COLUMN public.announcements.ends_at IS '结束展示时间（为空表示永久生效）';


--
-- Name: announcements_id_seq; Type: SEQUENCE; Schema: public; Owner: sub2api
--

CREATE SEQUENCE public.announcements_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.announcements_id_seq OWNER TO sub2api;

--
-- Name: announcements_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sub2api
--

ALTER SEQUENCE public.announcements_id_seq OWNED BY public.announcements.id;


--
-- Name: api_keys; Type: TABLE; Schema: public; Owner: sub2api
--

CREATE TABLE public.api_keys (
    id bigint NOT NULL,
    user_id bigint NOT NULL,
    key character varying(128) NOT NULL,
    name character varying(100) NOT NULL,
    group_id bigint,
    status character varying(20) DEFAULT 'active'::character varying NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone,
    ip_whitelist jsonb,
    ip_blacklist jsonb,
    quota numeric(20,8) DEFAULT 0 NOT NULL,
    quota_used numeric(20,8) DEFAULT 0 NOT NULL,
    expires_at timestamp with time zone,
    last_used_at timestamp with time zone
);


ALTER TABLE public.api_keys OWNER TO sub2api;

--
-- Name: COLUMN api_keys.ip_whitelist; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON COLUMN public.api_keys.ip_whitelist IS 'JSON array of allowed IPs/CIDRs, e.g. ["192.168.1.100", "10.0.0.0/8"]';


--
-- Name: COLUMN api_keys.ip_blacklist; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON COLUMN public.api_keys.ip_blacklist IS 'JSON array of blocked IPs/CIDRs, e.g. ["1.2.3.4", "5.6.0.0/16"]';


--
-- Name: COLUMN api_keys.quota; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON COLUMN public.api_keys.quota IS 'Quota limit in USD for this API key (0 = unlimited)';


--
-- Name: COLUMN api_keys.quota_used; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON COLUMN public.api_keys.quota_used IS 'Used quota amount in USD';


--
-- Name: COLUMN api_keys.expires_at; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON COLUMN public.api_keys.expires_at IS 'Expiration time for this API key (null = never expires)';


--
-- Name: api_keys_id_seq; Type: SEQUENCE; Schema: public; Owner: sub2api
--

CREATE SEQUENCE public.api_keys_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.api_keys_id_seq OWNER TO sub2api;

--
-- Name: api_keys_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sub2api
--

ALTER SEQUENCE public.api_keys_id_seq OWNED BY public.api_keys.id;


--
-- Name: atlas_schema_revisions; Type: TABLE; Schema: public; Owner: sub2api
--

CREATE TABLE public.atlas_schema_revisions (
    version text NOT NULL,
    description text NOT NULL,
    type integer NOT NULL,
    applied integer DEFAULT 0 NOT NULL,
    total integer DEFAULT 0 NOT NULL,
    executed_at timestamp with time zone DEFAULT now() NOT NULL,
    execution_time bigint DEFAULT 0 NOT NULL,
    error text,
    error_stmt text,
    hash text DEFAULT ''::text NOT NULL,
    partial_hashes text[],
    operator_version text
);


ALTER TABLE public.atlas_schema_revisions OWNER TO sub2api;

--
-- Name: billing_usage_entries; Type: TABLE; Schema: public; Owner: sub2api
--

CREATE TABLE public.billing_usage_entries (
    id bigint NOT NULL,
    usage_log_id bigint NOT NULL,
    user_id bigint NOT NULL,
    api_key_id bigint NOT NULL,
    subscription_id bigint,
    billing_type smallint NOT NULL,
    applied boolean DEFAULT true NOT NULL,
    delta_usd numeric(20,10) DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.billing_usage_entries OWNER TO sub2api;

--
-- Name: billing_usage_entries_id_seq; Type: SEQUENCE; Schema: public; Owner: sub2api
--

CREATE SEQUENCE public.billing_usage_entries_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.billing_usage_entries_id_seq OWNER TO sub2api;

--
-- Name: billing_usage_entries_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sub2api
--

ALTER SEQUENCE public.billing_usage_entries_id_seq OWNED BY public.billing_usage_entries.id;


--
-- Name: error_passthrough_rules; Type: TABLE; Schema: public; Owner: sub2api
--

CREATE TABLE public.error_passthrough_rules (
    id bigint NOT NULL,
    name character varying(100) NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    priority integer DEFAULT 0 NOT NULL,
    error_codes jsonb DEFAULT '[]'::jsonb,
    keywords jsonb DEFAULT '[]'::jsonb,
    match_mode character varying(10) DEFAULT 'any'::character varying NOT NULL,
    platforms jsonb DEFAULT '[]'::jsonb,
    passthrough_code boolean DEFAULT true NOT NULL,
    response_code integer,
    passthrough_body boolean DEFAULT true NOT NULL,
    custom_message text,
    description text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    skip_monitoring boolean DEFAULT false NOT NULL
);


ALTER TABLE public.error_passthrough_rules OWNER TO sub2api;

--
-- Name: error_passthrough_rules_id_seq; Type: SEQUENCE; Schema: public; Owner: sub2api
--

CREATE SEQUENCE public.error_passthrough_rules_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.error_passthrough_rules_id_seq OWNER TO sub2api;

--
-- Name: error_passthrough_rules_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sub2api
--

ALTER SEQUENCE public.error_passthrough_rules_id_seq OWNED BY public.error_passthrough_rules.id;


--
-- Name: groups; Type: TABLE; Schema: public; Owner: sub2api
--

CREATE TABLE public.groups (
    id bigint NOT NULL,
    name character varying(100) NOT NULL,
    description text,
    rate_multiplier numeric(10,4) DEFAULT 1.0 NOT NULL,
    is_exclusive boolean DEFAULT false NOT NULL,
    status character varying(20) DEFAULT 'active'::character varying NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone,
    platform character varying(50) DEFAULT 'anthropic'::character varying NOT NULL,
    subscription_type character varying(20) DEFAULT 'standard'::character varying NOT NULL,
    daily_limit_usd numeric(20,8) DEFAULT NULL::numeric,
    weekly_limit_usd numeric(20,8) DEFAULT NULL::numeric,
    monthly_limit_usd numeric(20,8) DEFAULT NULL::numeric,
    default_validity_days integer DEFAULT 30 NOT NULL,
    image_price_1k numeric(20,8),
    image_price_2k numeric(20,8),
    image_price_4k numeric(20,8),
    claude_code_only boolean DEFAULT false NOT NULL,
    fallback_group_id bigint,
    model_routing jsonb DEFAULT '{}'::jsonb,
    model_routing_enabled boolean DEFAULT false NOT NULL,
    fallback_group_id_on_invalid_request bigint,
    mcp_xml_inject boolean DEFAULT true NOT NULL,
    supported_model_scopes jsonb DEFAULT '["claude", "gemini_text", "gemini_image"]'::jsonb NOT NULL,
    sora_image_price_360 numeric(20,8),
    sora_image_price_540 numeric(20,8),
    sora_video_price_per_request numeric(20,8),
    sora_video_price_per_request_hd numeric(20,8),
    sort_order integer DEFAULT 0 NOT NULL
);


ALTER TABLE public.groups OWNER TO sub2api;

--
-- Name: COLUMN groups.image_price_1k; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON COLUMN public.groups.image_price_1k IS '1K 分辨率图片生成单价 (USD)，仅 antigravity 平台使用';


--
-- Name: COLUMN groups.image_price_2k; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON COLUMN public.groups.image_price_2k IS '2K 分辨率图片生成单价 (USD)，仅 antigravity 平台使用';


--
-- Name: COLUMN groups.image_price_4k; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON COLUMN public.groups.image_price_4k IS '4K 分辨率图片生成单价 (USD)，仅 antigravity 平台使用';


--
-- Name: COLUMN groups.claude_code_only; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON COLUMN public.groups.claude_code_only IS '是否仅允许 Claude Code 客户端访问此分组';


--
-- Name: COLUMN groups.fallback_group_id; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON COLUMN public.groups.fallback_group_id IS '非 Claude Code 请求降级使用的分组 ID';


--
-- Name: COLUMN groups.model_routing; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON COLUMN public.groups.model_routing IS '模型路由配置：{"model_pattern": [account_id1, account_id2], ...}，支持通配符匹配';


--
-- Name: COLUMN groups.fallback_group_id_on_invalid_request; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON COLUMN public.groups.fallback_group_id_on_invalid_request IS '无效请求兜底使用的分组 ID';


--
-- Name: COLUMN groups.supported_model_scopes; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON COLUMN public.groups.supported_model_scopes IS '支持的模型系列：claude, gemini_text, gemini_image';


--
-- Name: groups_id_seq; Type: SEQUENCE; Schema: public; Owner: sub2api
--

CREATE SEQUENCE public.groups_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.groups_id_seq OWNER TO sub2api;

--
-- Name: groups_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sub2api
--

ALTER SEQUENCE public.groups_id_seq OWNED BY public.groups.id;


--
-- Name: idempotency_records; Type: TABLE; Schema: public; Owner: sub2api
--

CREATE TABLE public.idempotency_records (
    id bigint NOT NULL,
    scope character varying(128) NOT NULL,
    idempotency_key_hash character varying(64) NOT NULL,
    request_fingerprint character varying(64) NOT NULL,
    status character varying(32) NOT NULL,
    response_status integer,
    response_body text,
    error_reason character varying(128),
    locked_until timestamp with time zone,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.idempotency_records OWNER TO sub2api;

--
-- Name: idempotency_records_id_seq; Type: SEQUENCE; Schema: public; Owner: sub2api
--

CREATE SEQUENCE public.idempotency_records_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.idempotency_records_id_seq OWNER TO sub2api;

--
-- Name: idempotency_records_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sub2api
--

ALTER SEQUENCE public.idempotency_records_id_seq OWNED BY public.idempotency_records.id;


--
-- Name: ops_alert_events; Type: TABLE; Schema: public; Owner: sub2api
--

CREATE TABLE public.ops_alert_events (
    id bigint NOT NULL,
    rule_id bigint,
    severity character varying(16) NOT NULL,
    status character varying(16) DEFAULT 'firing'::character varying NOT NULL,
    title character varying(200),
    description text,
    metric_value double precision,
    threshold_value double precision,
    dimensions jsonb,
    fired_at timestamp with time zone DEFAULT now() NOT NULL,
    resolved_at timestamp with time zone,
    email_sent boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.ops_alert_events OWNER TO sub2api;

--
-- Name: ops_alert_events_id_seq; Type: SEQUENCE; Schema: public; Owner: sub2api
--

CREATE SEQUENCE public.ops_alert_events_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.ops_alert_events_id_seq OWNER TO sub2api;

--
-- Name: ops_alert_events_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sub2api
--

ALTER SEQUENCE public.ops_alert_events_id_seq OWNED BY public.ops_alert_events.id;


--
-- Name: ops_alert_rules; Type: TABLE; Schema: public; Owner: sub2api
--

CREATE TABLE public.ops_alert_rules (
    id bigint NOT NULL,
    name character varying(128) NOT NULL,
    description text,
    enabled boolean DEFAULT true NOT NULL,
    severity character varying(16) DEFAULT 'warning'::character varying NOT NULL,
    metric_type character varying(64) NOT NULL,
    operator character varying(8) NOT NULL,
    threshold double precision NOT NULL,
    window_minutes integer DEFAULT 5 NOT NULL,
    sustained_minutes integer DEFAULT 5 NOT NULL,
    cooldown_minutes integer DEFAULT 10 NOT NULL,
    filters jsonb,
    last_triggered_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    notify_email boolean DEFAULT true NOT NULL
);


ALTER TABLE public.ops_alert_rules OWNER TO sub2api;

--
-- Name: ops_alert_rules_id_seq; Type: SEQUENCE; Schema: public; Owner: sub2api
--

CREATE SEQUENCE public.ops_alert_rules_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.ops_alert_rules_id_seq OWNER TO sub2api;

--
-- Name: ops_alert_rules_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sub2api
--

ALTER SEQUENCE public.ops_alert_rules_id_seq OWNED BY public.ops_alert_rules.id;


--
-- Name: ops_error_logs; Type: TABLE; Schema: public; Owner: sub2api
--

CREATE TABLE public.ops_error_logs (
    id bigint NOT NULL,
    request_id character varying(64),
    client_request_id character varying(64),
    user_id bigint,
    api_key_id bigint,
    account_id bigint,
    group_id bigint,
    client_ip inet,
    platform character varying(32),
    model character varying(100),
    request_path character varying(256),
    stream boolean DEFAULT false NOT NULL,
    user_agent text,
    error_phase character varying(32) NOT NULL,
    error_type character varying(64) NOT NULL,
    severity character varying(8) DEFAULT 'P2'::character varying NOT NULL,
    status_code integer,
    is_business_limited boolean DEFAULT false NOT NULL,
    error_message text,
    error_body text,
    error_source character varying(64),
    error_owner character varying(32),
    account_status character varying(50),
    upstream_status_code integer,
    upstream_error_message text,
    upstream_error_detail text,
    provider_error_code character varying(64),
    provider_error_type character varying(64),
    network_error_type character varying(50),
    retry_after_seconds integer,
    duration_ms integer,
    time_to_first_token_ms bigint,
    auth_latency_ms bigint,
    routing_latency_ms bigint,
    upstream_latency_ms bigint,
    response_latency_ms bigint,
    request_body jsonb,
    request_headers jsonb,
    request_body_truncated boolean DEFAULT false NOT NULL,
    request_body_bytes integer,
    is_retryable boolean DEFAULT false NOT NULL,
    retry_count integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    upstream_errors jsonb,
    is_count_tokens boolean DEFAULT false NOT NULL,
    resolved boolean DEFAULT false NOT NULL,
    resolved_at timestamp with time zone,
    resolved_by_user_id bigint,
    resolved_retry_id bigint
);


ALTER TABLE public.ops_error_logs OWNER TO sub2api;

--
-- Name: TABLE ops_error_logs; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON TABLE public.ops_error_logs IS 'Ops error logs (vNext). Stores sanitized error details and request_body for retries (errors only).';


--
-- Name: COLUMN ops_error_logs.upstream_errors; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON COLUMN public.ops_error_logs.upstream_errors IS 'Sanitized upstream error events list (JSON array), correlated per gateway request (request_id/client_request_id); used for per-request upstream debugging.';


--
-- Name: COLUMN ops_error_logs.is_count_tokens; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON COLUMN public.ops_error_logs.is_count_tokens IS '是否为 count_tokens 请求的错误（用于统计过滤）';


--
-- Name: ops_error_logs_id_seq; Type: SEQUENCE; Schema: public; Owner: sub2api
--

CREATE SEQUENCE public.ops_error_logs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.ops_error_logs_id_seq OWNER TO sub2api;

--
-- Name: ops_error_logs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sub2api
--

ALTER SEQUENCE public.ops_error_logs_id_seq OWNED BY public.ops_error_logs.id;


--
-- Name: ops_job_heartbeats; Type: TABLE; Schema: public; Owner: sub2api
--

CREATE TABLE public.ops_job_heartbeats (
    job_name character varying(64) NOT NULL,
    last_run_at timestamp with time zone,
    last_success_at timestamp with time zone,
    last_error_at timestamp with time zone,
    last_error text,
    last_duration_ms bigint,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    last_result text
);


ALTER TABLE public.ops_job_heartbeats OWNER TO sub2api;

--
-- Name: TABLE ops_job_heartbeats; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON TABLE public.ops_job_heartbeats IS 'Ops background jobs heartbeats (vNext).';


--
-- Name: COLUMN ops_job_heartbeats.last_result; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON COLUMN public.ops_job_heartbeats.last_result IS 'Last successful run result summary (human readable).';


--
-- Name: ops_metrics_daily; Type: TABLE; Schema: public; Owner: sub2api
--

CREATE TABLE public.ops_metrics_daily (
    id bigint NOT NULL,
    bucket_date date NOT NULL,
    platform character varying(32),
    group_id bigint,
    success_count bigint DEFAULT 0 NOT NULL,
    error_count_total bigint DEFAULT 0 NOT NULL,
    business_limited_count bigint DEFAULT 0 NOT NULL,
    error_count_sla bigint DEFAULT 0 NOT NULL,
    upstream_error_count_excl_429_529 bigint DEFAULT 0 NOT NULL,
    upstream_429_count bigint DEFAULT 0 NOT NULL,
    upstream_529_count bigint DEFAULT 0 NOT NULL,
    token_consumed bigint DEFAULT 0 NOT NULL,
    duration_p50_ms integer,
    duration_p90_ms integer,
    duration_p95_ms integer,
    duration_p99_ms integer,
    ttft_p50_ms integer,
    ttft_p90_ms integer,
    ttft_p95_ms integer,
    ttft_p99_ms integer,
    computed_at timestamp with time zone DEFAULT now() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    duration_avg_ms double precision,
    duration_max_ms integer,
    ttft_avg_ms double precision,
    ttft_max_ms integer
);


ALTER TABLE public.ops_metrics_daily OWNER TO sub2api;

--
-- Name: TABLE ops_metrics_daily; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON TABLE public.ops_metrics_daily IS 'vNext daily pre-aggregated ops metrics (overall/platform/group).';


--
-- Name: ops_metrics_daily_id_seq; Type: SEQUENCE; Schema: public; Owner: sub2api
--

CREATE SEQUENCE public.ops_metrics_daily_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.ops_metrics_daily_id_seq OWNER TO sub2api;

--
-- Name: ops_metrics_daily_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sub2api
--

ALTER SEQUENCE public.ops_metrics_daily_id_seq OWNED BY public.ops_metrics_daily.id;


--
-- Name: ops_metrics_hourly; Type: TABLE; Schema: public; Owner: sub2api
--

CREATE TABLE public.ops_metrics_hourly (
    id bigint NOT NULL,
    bucket_start timestamp with time zone NOT NULL,
    platform character varying(32),
    group_id bigint,
    success_count bigint DEFAULT 0 NOT NULL,
    error_count_total bigint DEFAULT 0 NOT NULL,
    business_limited_count bigint DEFAULT 0 NOT NULL,
    error_count_sla bigint DEFAULT 0 NOT NULL,
    upstream_error_count_excl_429_529 bigint DEFAULT 0 NOT NULL,
    upstream_429_count bigint DEFAULT 0 NOT NULL,
    upstream_529_count bigint DEFAULT 0 NOT NULL,
    token_consumed bigint DEFAULT 0 NOT NULL,
    duration_p50_ms integer,
    duration_p90_ms integer,
    duration_p95_ms integer,
    duration_p99_ms integer,
    ttft_p50_ms integer,
    ttft_p90_ms integer,
    ttft_p95_ms integer,
    ttft_p99_ms integer,
    computed_at timestamp with time zone DEFAULT now() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    duration_avg_ms double precision,
    duration_max_ms integer,
    ttft_avg_ms double precision,
    ttft_max_ms integer
);


ALTER TABLE public.ops_metrics_hourly OWNER TO sub2api;

--
-- Name: TABLE ops_metrics_hourly; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON TABLE public.ops_metrics_hourly IS 'vNext hourly pre-aggregated ops metrics (overall/platform/group).';


--
-- Name: ops_metrics_hourly_id_seq; Type: SEQUENCE; Schema: public; Owner: sub2api
--

CREATE SEQUENCE public.ops_metrics_hourly_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.ops_metrics_hourly_id_seq OWNER TO sub2api;

--
-- Name: ops_metrics_hourly_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sub2api
--

ALTER SEQUENCE public.ops_metrics_hourly_id_seq OWNED BY public.ops_metrics_hourly.id;


--
-- Name: ops_retry_attempts; Type: TABLE; Schema: public; Owner: sub2api
--

CREATE TABLE public.ops_retry_attempts (
    id bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    requested_by_user_id bigint,
    source_error_id bigint,
    mode character varying(16) NOT NULL,
    pinned_account_id bigint,
    status character varying(16) DEFAULT 'queued'::character varying NOT NULL,
    started_at timestamp with time zone,
    finished_at timestamp with time zone,
    duration_ms bigint,
    result_request_id character varying(64),
    result_error_id bigint,
    result_usage_request_id character varying(64),
    error_message text,
    success boolean,
    http_status_code integer,
    upstream_request_id character varying(128),
    used_account_id bigint,
    response_preview text,
    response_truncated boolean DEFAULT false NOT NULL
);


ALTER TABLE public.ops_retry_attempts OWNER TO sub2api;

--
-- Name: TABLE ops_retry_attempts; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON TABLE public.ops_retry_attempts IS 'Audit table for ops retries (client retry / pinned upstream retry).';


--
-- Name: ops_retry_attempts_id_seq; Type: SEQUENCE; Schema: public; Owner: sub2api
--

CREATE SEQUENCE public.ops_retry_attempts_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.ops_retry_attempts_id_seq OWNER TO sub2api;

--
-- Name: ops_retry_attempts_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sub2api
--

ALTER SEQUENCE public.ops_retry_attempts_id_seq OWNED BY public.ops_retry_attempts.id;


--
-- Name: ops_system_log_cleanup_audits; Type: TABLE; Schema: public; Owner: sub2api
--

CREATE TABLE public.ops_system_log_cleanup_audits (
    id bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    operator_id bigint NOT NULL,
    conditions jsonb DEFAULT '{}'::jsonb NOT NULL,
    deleted_rows bigint DEFAULT 0 NOT NULL
);


ALTER TABLE public.ops_system_log_cleanup_audits OWNER TO sub2api;

--
-- Name: ops_system_log_cleanup_audits_id_seq; Type: SEQUENCE; Schema: public; Owner: sub2api
--

CREATE SEQUENCE public.ops_system_log_cleanup_audits_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.ops_system_log_cleanup_audits_id_seq OWNER TO sub2api;

--
-- Name: ops_system_log_cleanup_audits_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sub2api
--

ALTER SEQUENCE public.ops_system_log_cleanup_audits_id_seq OWNED BY public.ops_system_log_cleanup_audits.id;


--
-- Name: ops_system_logs; Type: TABLE; Schema: public; Owner: sub2api
--

CREATE TABLE public.ops_system_logs (
    id bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    level character varying(16) NOT NULL,
    component character varying(128) DEFAULT ''::character varying NOT NULL,
    message text NOT NULL,
    request_id character varying(128),
    client_request_id character varying(128),
    user_id bigint,
    account_id bigint,
    platform character varying(32),
    model character varying(128),
    extra jsonb DEFAULT '{}'::jsonb NOT NULL
);


ALTER TABLE public.ops_system_logs OWNER TO sub2api;

--
-- Name: ops_system_logs_id_seq; Type: SEQUENCE; Schema: public; Owner: sub2api
--

CREATE SEQUENCE public.ops_system_logs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.ops_system_logs_id_seq OWNER TO sub2api;

--
-- Name: ops_system_logs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sub2api
--

ALTER SEQUENCE public.ops_system_logs_id_seq OWNED BY public.ops_system_logs.id;


--
-- Name: ops_system_metrics; Type: TABLE; Schema: public; Owner: sub2api
--

CREATE TABLE public.ops_system_metrics (
    id bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    window_minutes integer DEFAULT 1 NOT NULL,
    platform character varying(32),
    group_id bigint,
    success_count bigint DEFAULT 0 NOT NULL,
    error_count_total bigint DEFAULT 0 NOT NULL,
    business_limited_count bigint DEFAULT 0 NOT NULL,
    error_count_sla bigint DEFAULT 0 NOT NULL,
    upstream_error_count_excl_429_529 bigint DEFAULT 0 NOT NULL,
    upstream_429_count bigint DEFAULT 0 NOT NULL,
    upstream_529_count bigint DEFAULT 0 NOT NULL,
    token_consumed bigint DEFAULT 0 NOT NULL,
    qps double precision,
    tps double precision,
    duration_p50_ms integer,
    duration_p90_ms integer,
    duration_p95_ms integer,
    duration_p99_ms integer,
    duration_avg_ms double precision,
    duration_max_ms integer,
    ttft_p50_ms integer,
    ttft_p90_ms integer,
    ttft_p95_ms integer,
    ttft_p99_ms integer,
    ttft_avg_ms double precision,
    ttft_max_ms integer,
    cpu_usage_percent double precision,
    memory_used_mb bigint,
    memory_total_mb bigint,
    memory_usage_percent double precision,
    db_ok boolean,
    redis_ok boolean,
    db_conn_active integer,
    db_conn_idle integer,
    db_conn_waiting integer,
    goroutine_count integer,
    concurrency_queue_depth integer,
    redis_conn_total integer,
    redis_conn_idle integer,
    account_switch_count bigint DEFAULT 0 NOT NULL
);


ALTER TABLE public.ops_system_metrics OWNER TO sub2api;

--
-- Name: TABLE ops_system_metrics; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON TABLE public.ops_system_metrics IS 'Ops system/request metrics snapshots (vNext). Used for dashboard overview and realtime rates.';


--
-- Name: COLUMN ops_system_metrics.redis_conn_total; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON COLUMN public.ops_system_metrics.redis_conn_total IS 'Redis pool total connections (go-redis PoolStats.TotalConns).';


--
-- Name: COLUMN ops_system_metrics.redis_conn_idle; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON COLUMN public.ops_system_metrics.redis_conn_idle IS 'Redis pool idle connections (go-redis PoolStats.IdleConns).';


--
-- Name: ops_system_metrics_id_seq; Type: SEQUENCE; Schema: public; Owner: sub2api
--

CREATE SEQUENCE public.ops_system_metrics_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.ops_system_metrics_id_seq OWNER TO sub2api;

--
-- Name: ops_system_metrics_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sub2api
--

ALTER SEQUENCE public.ops_system_metrics_id_seq OWNED BY public.ops_system_metrics.id;


--
-- Name: orphan_allowed_groups_audit; Type: TABLE; Schema: public; Owner: sub2api
--

CREATE TABLE public.orphan_allowed_groups_audit (
    id bigint NOT NULL,
    user_id bigint NOT NULL,
    group_id bigint NOT NULL,
    recorded_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.orphan_allowed_groups_audit OWNER TO sub2api;

--
-- Name: TABLE orphan_allowed_groups_audit; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON TABLE public.orphan_allowed_groups_audit IS '审计表：记录 users.allowed_groups 中引用的不存在的 group_id，用于数据清理前的审计';


--
-- Name: orphan_allowed_groups_audit_id_seq; Type: SEQUENCE; Schema: public; Owner: sub2api
--

CREATE SEQUENCE public.orphan_allowed_groups_audit_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.orphan_allowed_groups_audit_id_seq OWNER TO sub2api;

--
-- Name: orphan_allowed_groups_audit_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sub2api
--

ALTER SEQUENCE public.orphan_allowed_groups_audit_id_seq OWNED BY public.orphan_allowed_groups_audit.id;


--
-- Name: promo_code_usages; Type: TABLE; Schema: public; Owner: sub2api
--

CREATE TABLE public.promo_code_usages (
    id bigint NOT NULL,
    promo_code_id bigint NOT NULL,
    user_id bigint NOT NULL,
    bonus_amount numeric(20,8) NOT NULL,
    used_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.promo_code_usages OWNER TO sub2api;

--
-- Name: TABLE promo_code_usages; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON TABLE public.promo_code_usages IS '优惠码使用记录';


--
-- Name: promo_code_usages_id_seq; Type: SEQUENCE; Schema: public; Owner: sub2api
--

CREATE SEQUENCE public.promo_code_usages_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.promo_code_usages_id_seq OWNER TO sub2api;

--
-- Name: promo_code_usages_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sub2api
--

ALTER SEQUENCE public.promo_code_usages_id_seq OWNED BY public.promo_code_usages.id;


--
-- Name: promo_codes; Type: TABLE; Schema: public; Owner: sub2api
--

CREATE TABLE public.promo_codes (
    id bigint NOT NULL,
    code character varying(32) NOT NULL,
    bonus_amount numeric(20,8) DEFAULT 0 NOT NULL,
    max_uses integer DEFAULT 0 NOT NULL,
    used_count integer DEFAULT 0 NOT NULL,
    status character varying(20) DEFAULT 'active'::character varying NOT NULL,
    expires_at timestamp with time zone,
    notes text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.promo_codes OWNER TO sub2api;

--
-- Name: TABLE promo_codes; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON TABLE public.promo_codes IS '注册优惠码';


--
-- Name: COLUMN promo_codes.max_uses; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON COLUMN public.promo_codes.max_uses IS '最大使用次数，0表示无限制';


--
-- Name: COLUMN promo_codes.status; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON COLUMN public.promo_codes.status IS '状态: active, disabled';


--
-- Name: promo_codes_id_seq; Type: SEQUENCE; Schema: public; Owner: sub2api
--

CREATE SEQUENCE public.promo_codes_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.promo_codes_id_seq OWNER TO sub2api;

--
-- Name: promo_codes_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sub2api
--

ALTER SEQUENCE public.promo_codes_id_seq OWNED BY public.promo_codes.id;


--
-- Name: proxies; Type: TABLE; Schema: public; Owner: sub2api
--

CREATE TABLE public.proxies (
    id bigint NOT NULL,
    name character varying(100) NOT NULL,
    protocol character varying(20) NOT NULL,
    host character varying(255) NOT NULL,
    port integer NOT NULL,
    username character varying(100),
    password character varying(100),
    status character varying(20) DEFAULT 'active'::character varying NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone
);


ALTER TABLE public.proxies OWNER TO sub2api;

--
-- Name: proxies_id_seq; Type: SEQUENCE; Schema: public; Owner: sub2api
--

CREATE SEQUENCE public.proxies_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.proxies_id_seq OWNER TO sub2api;

--
-- Name: proxies_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sub2api
--

ALTER SEQUENCE public.proxies_id_seq OWNED BY public.proxies.id;


--
-- Name: redeem_codes; Type: TABLE; Schema: public; Owner: sub2api
--

CREATE TABLE public.redeem_codes (
    id bigint NOT NULL,
    code character varying(32) NOT NULL,
    type character varying(20) DEFAULT 'balance'::character varying NOT NULL,
    value numeric(20,8) NOT NULL,
    status character varying(20) DEFAULT 'unused'::character varying NOT NULL,
    used_by bigint,
    used_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    notes text,
    group_id bigint,
    validity_days integer DEFAULT 30 NOT NULL
);


ALTER TABLE public.redeem_codes OWNER TO sub2api;

--
-- Name: COLUMN redeem_codes.notes; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON COLUMN public.redeem_codes.notes IS '备注说明（管理员调整时的原因说明）';


--
-- Name: redeem_codes_id_seq; Type: SEQUENCE; Schema: public; Owner: sub2api
--

CREATE SEQUENCE public.redeem_codes_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.redeem_codes_id_seq OWNER TO sub2api;

--
-- Name: redeem_codes_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sub2api
--

ALTER SEQUENCE public.redeem_codes_id_seq OWNED BY public.redeem_codes.id;


--
-- Name: scheduler_outbox; Type: TABLE; Schema: public; Owner: sub2api
--

CREATE TABLE public.scheduler_outbox (
    id bigint NOT NULL,
    event_type text NOT NULL,
    account_id bigint,
    group_id bigint,
    payload jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.scheduler_outbox OWNER TO sub2api;

--
-- Name: scheduler_outbox_id_seq; Type: SEQUENCE; Schema: public; Owner: sub2api
--

CREATE SEQUENCE public.scheduler_outbox_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.scheduler_outbox_id_seq OWNER TO sub2api;

--
-- Name: scheduler_outbox_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sub2api
--

ALTER SEQUENCE public.scheduler_outbox_id_seq OWNED BY public.scheduler_outbox.id;


--
-- Name: schema_migrations; Type: TABLE; Schema: public; Owner: sub2api
--

CREATE TABLE public.schema_migrations (
    filename text NOT NULL,
    checksum text NOT NULL,
    applied_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.schema_migrations OWNER TO sub2api;

--
-- Name: security_secrets; Type: TABLE; Schema: public; Owner: sub2api
--

CREATE TABLE public.security_secrets (
    id bigint NOT NULL,
    key character varying(100) NOT NULL,
    value text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.security_secrets OWNER TO sub2api;

--
-- Name: security_secrets_id_seq; Type: SEQUENCE; Schema: public; Owner: sub2api
--

CREATE SEQUENCE public.security_secrets_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.security_secrets_id_seq OWNER TO sub2api;

--
-- Name: security_secrets_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sub2api
--

ALTER SEQUENCE public.security_secrets_id_seq OWNED BY public.security_secrets.id;


--
-- Name: settings; Type: TABLE; Schema: public; Owner: sub2api
--

CREATE TABLE public.settings (
    id bigint NOT NULL,
    key character varying(100) NOT NULL,
    value text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.settings OWNER TO sub2api;

--
-- Name: settings_id_seq; Type: SEQUENCE; Schema: public; Owner: sub2api
--

CREATE SEQUENCE public.settings_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.settings_id_seq OWNER TO sub2api;

--
-- Name: settings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sub2api
--

ALTER SEQUENCE public.settings_id_seq OWNED BY public.settings.id;


--
-- Name: sora_accounts; Type: TABLE; Schema: public; Owner: sub2api
--

CREATE TABLE public.sora_accounts (
    account_id bigint NOT NULL,
    access_token text NOT NULL,
    refresh_token text NOT NULL,
    session_token text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.sora_accounts OWNER TO sub2api;

--
-- Name: usage_cleanup_tasks; Type: TABLE; Schema: public; Owner: sub2api
--

CREATE TABLE public.usage_cleanup_tasks (
    id bigint NOT NULL,
    status character varying(20) NOT NULL,
    filters jsonb NOT NULL,
    created_by bigint NOT NULL,
    deleted_rows bigint DEFAULT 0 NOT NULL,
    error_message text,
    started_at timestamp with time zone,
    finished_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    canceled_by bigint,
    canceled_at timestamp with time zone
);


ALTER TABLE public.usage_cleanup_tasks OWNER TO sub2api;

--
-- Name: usage_cleanup_tasks_id_seq; Type: SEQUENCE; Schema: public; Owner: sub2api
--

CREATE SEQUENCE public.usage_cleanup_tasks_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.usage_cleanup_tasks_id_seq OWNER TO sub2api;

--
-- Name: usage_cleanup_tasks_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sub2api
--

ALTER SEQUENCE public.usage_cleanup_tasks_id_seq OWNED BY public.usage_cleanup_tasks.id;


--
-- Name: usage_dashboard_aggregation_watermark; Type: TABLE; Schema: public; Owner: sub2api
--

CREATE TABLE public.usage_dashboard_aggregation_watermark (
    id integer NOT NULL,
    last_aggregated_at timestamp with time zone DEFAULT '1970-01-01 08:00:00+08'::timestamp with time zone CONSTRAINT usage_dashboard_aggregation_waterma_last_aggregated_at_not_null NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.usage_dashboard_aggregation_watermark OWNER TO sub2api;

--
-- Name: usage_dashboard_daily; Type: TABLE; Schema: public; Owner: sub2api
--

CREATE TABLE public.usage_dashboard_daily (
    bucket_date date NOT NULL,
    total_requests bigint DEFAULT 0 NOT NULL,
    input_tokens bigint DEFAULT 0 NOT NULL,
    output_tokens bigint DEFAULT 0 NOT NULL,
    cache_creation_tokens bigint DEFAULT 0 NOT NULL,
    cache_read_tokens bigint DEFAULT 0 NOT NULL,
    total_cost numeric(20,10) DEFAULT 0 NOT NULL,
    actual_cost numeric(20,10) DEFAULT 0 NOT NULL,
    total_duration_ms bigint DEFAULT 0 NOT NULL,
    active_users bigint DEFAULT 0 NOT NULL,
    computed_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.usage_dashboard_daily OWNER TO sub2api;

--
-- Name: TABLE usage_dashboard_daily; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON TABLE public.usage_dashboard_daily IS 'Pre-aggregated daily usage metrics for admin dashboard (UTC dates).';


--
-- Name: COLUMN usage_dashboard_daily.bucket_date; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON COLUMN public.usage_dashboard_daily.bucket_date IS 'UTC date of the day bucket.';


--
-- Name: COLUMN usage_dashboard_daily.computed_at; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON COLUMN public.usage_dashboard_daily.computed_at IS 'When the daily row was last computed/refreshed.';


--
-- Name: usage_dashboard_daily_users; Type: TABLE; Schema: public; Owner: sub2api
--

CREATE TABLE public.usage_dashboard_daily_users (
    bucket_date date NOT NULL,
    user_id bigint NOT NULL
);


ALTER TABLE public.usage_dashboard_daily_users OWNER TO sub2api;

--
-- Name: usage_dashboard_hourly; Type: TABLE; Schema: public; Owner: sub2api
--

CREATE TABLE public.usage_dashboard_hourly (
    bucket_start timestamp with time zone NOT NULL,
    total_requests bigint DEFAULT 0 NOT NULL,
    input_tokens bigint DEFAULT 0 NOT NULL,
    output_tokens bigint DEFAULT 0 NOT NULL,
    cache_creation_tokens bigint DEFAULT 0 NOT NULL,
    cache_read_tokens bigint DEFAULT 0 NOT NULL,
    total_cost numeric(20,10) DEFAULT 0 NOT NULL,
    actual_cost numeric(20,10) DEFAULT 0 NOT NULL,
    total_duration_ms bigint DEFAULT 0 NOT NULL,
    active_users bigint DEFAULT 0 NOT NULL,
    computed_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.usage_dashboard_hourly OWNER TO sub2api;

--
-- Name: TABLE usage_dashboard_hourly; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON TABLE public.usage_dashboard_hourly IS 'Pre-aggregated hourly usage metrics for admin dashboard (UTC buckets).';


--
-- Name: COLUMN usage_dashboard_hourly.bucket_start; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON COLUMN public.usage_dashboard_hourly.bucket_start IS 'UTC start timestamp of the hour bucket.';


--
-- Name: COLUMN usage_dashboard_hourly.computed_at; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON COLUMN public.usage_dashboard_hourly.computed_at IS 'When the hourly row was last computed/refreshed.';


--
-- Name: usage_dashboard_hourly_users; Type: TABLE; Schema: public; Owner: sub2api
--

CREATE TABLE public.usage_dashboard_hourly_users (
    bucket_start timestamp with time zone NOT NULL,
    user_id bigint NOT NULL
);


ALTER TABLE public.usage_dashboard_hourly_users OWNER TO sub2api;

--
-- Name: usage_logs; Type: TABLE; Schema: public; Owner: sub2api
--

CREATE TABLE public.usage_logs (
    id bigint NOT NULL,
    user_id bigint NOT NULL,
    api_key_id bigint NOT NULL,
    account_id bigint NOT NULL,
    request_id character varying(64),
    model character varying(100) NOT NULL,
    input_tokens integer DEFAULT 0 NOT NULL,
    output_tokens integer DEFAULT 0 NOT NULL,
    cache_creation_tokens integer DEFAULT 0 NOT NULL,
    cache_read_tokens integer DEFAULT 0 NOT NULL,
    cache_creation_5m_tokens integer DEFAULT 0 NOT NULL,
    cache_creation_1h_tokens integer DEFAULT 0 NOT NULL,
    input_cost numeric(20,10) DEFAULT 0 NOT NULL,
    output_cost numeric(20,10) DEFAULT 0 NOT NULL,
    cache_creation_cost numeric(20,10) DEFAULT 0 NOT NULL,
    cache_read_cost numeric(20,10) DEFAULT 0 NOT NULL,
    total_cost numeric(20,10) DEFAULT 0 NOT NULL,
    actual_cost numeric(20,10) DEFAULT 0 NOT NULL,
    stream boolean DEFAULT false NOT NULL,
    duration_ms integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    group_id bigint,
    subscription_id bigint,
    rate_multiplier numeric(10,4) DEFAULT 1 NOT NULL,
    first_token_ms integer,
    billing_type smallint DEFAULT 0 NOT NULL,
    user_agent character varying(512),
    image_count integer DEFAULT 0,
    image_size character varying(10),
    ip_address character varying(45),
    account_rate_multiplier numeric(10,4),
    reasoning_effort character varying(20),
    media_type character varying(16),
    cache_ttl_overridden boolean DEFAULT false NOT NULL
);


ALTER TABLE public.usage_logs OWNER TO sub2api;

--
-- Name: COLUMN usage_logs.user_agent; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON COLUMN public.usage_logs.user_agent IS 'User-Agent header from the API request';


--
-- Name: usage_logs_id_seq; Type: SEQUENCE; Schema: public; Owner: sub2api
--

CREATE SEQUENCE public.usage_logs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.usage_logs_id_seq OWNER TO sub2api;

--
-- Name: usage_logs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sub2api
--

ALTER SEQUENCE public.usage_logs_id_seq OWNED BY public.usage_logs.id;


--
-- Name: user_allowed_groups; Type: TABLE; Schema: public; Owner: sub2api
--

CREATE TABLE public.user_allowed_groups (
    user_id bigint NOT NULL,
    group_id bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.user_allowed_groups OWNER TO sub2api;

--
-- Name: user_attribute_definitions; Type: TABLE; Schema: public; Owner: sub2api
--

CREATE TABLE public.user_attribute_definitions (
    id bigint NOT NULL,
    key character varying(100) NOT NULL,
    name character varying(255) NOT NULL,
    description text DEFAULT ''::text,
    type character varying(20) NOT NULL,
    options jsonb DEFAULT '[]'::jsonb,
    required boolean DEFAULT false NOT NULL,
    validation jsonb DEFAULT '{}'::jsonb,
    placeholder character varying(255) DEFAULT ''::character varying,
    display_order integer DEFAULT 0 NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone
);


ALTER TABLE public.user_attribute_definitions OWNER TO sub2api;

--
-- Name: user_attribute_definitions_id_seq; Type: SEQUENCE; Schema: public; Owner: sub2api
--

CREATE SEQUENCE public.user_attribute_definitions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.user_attribute_definitions_id_seq OWNER TO sub2api;

--
-- Name: user_attribute_definitions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sub2api
--

ALTER SEQUENCE public.user_attribute_definitions_id_seq OWNED BY public.user_attribute_definitions.id;


--
-- Name: user_attribute_values; Type: TABLE; Schema: public; Owner: sub2api
--

CREATE TABLE public.user_attribute_values (
    id bigint NOT NULL,
    user_id bigint NOT NULL,
    attribute_id bigint NOT NULL,
    value text DEFAULT ''::text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.user_attribute_values OWNER TO sub2api;

--
-- Name: user_attribute_values_id_seq; Type: SEQUENCE; Schema: public; Owner: sub2api
--

CREATE SEQUENCE public.user_attribute_values_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.user_attribute_values_id_seq OWNER TO sub2api;

--
-- Name: user_attribute_values_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sub2api
--

ALTER SEQUENCE public.user_attribute_values_id_seq OWNED BY public.user_attribute_values.id;


--
-- Name: user_group_rate_multipliers; Type: TABLE; Schema: public; Owner: sub2api
--

CREATE TABLE public.user_group_rate_multipliers (
    user_id bigint NOT NULL,
    group_id bigint NOT NULL,
    rate_multiplier numeric(10,4) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.user_group_rate_multipliers OWNER TO sub2api;

--
-- Name: TABLE user_group_rate_multipliers; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON TABLE public.user_group_rate_multipliers IS '用户专属分组倍率配置';


--
-- Name: COLUMN user_group_rate_multipliers.user_id; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON COLUMN public.user_group_rate_multipliers.user_id IS '用户ID';


--
-- Name: COLUMN user_group_rate_multipliers.group_id; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON COLUMN public.user_group_rate_multipliers.group_id IS '分组ID';


--
-- Name: COLUMN user_group_rate_multipliers.rate_multiplier; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON COLUMN public.user_group_rate_multipliers.rate_multiplier IS '专属计费倍率（覆盖分组默认倍率）';


--
-- Name: user_ldap_profiles; Type: TABLE; Schema: public; Owner: sub2api
--

CREATE TABLE public.user_ldap_profiles (
    user_id bigint NOT NULL,
    ldap_uid character varying(255) NOT NULL,
    ldap_username character varying(255) NOT NULL,
    ldap_email character varying(255) DEFAULT ''::character varying NOT NULL,
    display_name character varying(255) DEFAULT ''::character varying NOT NULL,
    department character varying(255) DEFAULT ''::character varying NOT NULL,
    groups_hash character varying(128) DEFAULT ''::character varying NOT NULL,
    active boolean DEFAULT true NOT NULL,
    last_synced_at timestamp with time zone DEFAULT now() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.user_ldap_profiles OWNER TO sub2api;

--
-- Name: user_subscriptions; Type: TABLE; Schema: public; Owner: sub2api
--

CREATE TABLE public.user_subscriptions (
    id bigint NOT NULL,
    user_id bigint NOT NULL,
    group_id bigint NOT NULL,
    starts_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    status character varying(20) DEFAULT 'active'::character varying NOT NULL,
    daily_window_start timestamp with time zone,
    weekly_window_start timestamp with time zone,
    monthly_window_start timestamp with time zone,
    daily_usage_usd numeric(20,10) DEFAULT 0 NOT NULL,
    weekly_usage_usd numeric(20,10) DEFAULT 0 NOT NULL,
    monthly_usage_usd numeric(20,10) DEFAULT 0 NOT NULL,
    assigned_by bigint,
    assigned_at timestamp with time zone DEFAULT now() NOT NULL,
    notes text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone
);


ALTER TABLE public.user_subscriptions OWNER TO sub2api;

--
-- Name: COLUMN user_subscriptions.deleted_at; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON COLUMN public.user_subscriptions.deleted_at IS '软删除时间戳，NULL 表示未删除';


--
-- Name: user_subscriptions_id_seq; Type: SEQUENCE; Schema: public; Owner: sub2api
--

CREATE SEQUENCE public.user_subscriptions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.user_subscriptions_id_seq OWNER TO sub2api;

--
-- Name: user_subscriptions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sub2api
--

ALTER SEQUENCE public.user_subscriptions_id_seq OWNED BY public.user_subscriptions.id;


--
-- Name: users; Type: TABLE; Schema: public; Owner: sub2api
--

CREATE TABLE public.users (
    id bigint NOT NULL,
    email character varying(255) NOT NULL,
    password_hash character varying(255) NOT NULL,
    role character varying(20) DEFAULT 'user'::character varying NOT NULL,
    balance numeric(20,8) DEFAULT 0 NOT NULL,
    concurrency integer DEFAULT 5 NOT NULL,
    status character varying(20) DEFAULT 'active'::character varying NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone,
    username character varying(100) DEFAULT ''::character varying NOT NULL,
    notes text DEFAULT ''::text NOT NULL,
    wechat character varying(100) DEFAULT ''::character varying,
    totp_secret_encrypted text,
    totp_enabled boolean DEFAULT false NOT NULL,
    totp_enabled_at timestamp with time zone,
    token_version bigint DEFAULT 0 NOT NULL,
    auth_source character varying(20) DEFAULT 'local'::character varying NOT NULL
);


ALTER TABLE public.users OWNER TO sub2api;

--
-- Name: TABLE users; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON TABLE public.users IS '用户表。注：原 allowed_groups BIGINT[] 列已迁移至 user_allowed_groups 联接表';


--
-- Name: COLUMN users.totp_secret_encrypted; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON COLUMN public.users.totp_secret_encrypted IS 'AES-256-GCM 加密的 TOTP 密钥';


--
-- Name: COLUMN users.totp_enabled; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON COLUMN public.users.totp_enabled IS '是否启用 TOTP 双因素认证';


--
-- Name: COLUMN users.totp_enabled_at; Type: COMMENT; Schema: public; Owner: sub2api
--

COMMENT ON COLUMN public.users.totp_enabled_at IS 'TOTP 启用时间';


--
-- Name: users_id_seq; Type: SEQUENCE; Schema: public; Owner: sub2api
--

CREATE SEQUENCE public.users_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.users_id_seq OWNER TO sub2api;

--
-- Name: users_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sub2api
--

ALTER SEQUENCE public.users_id_seq OWNED BY public.users.id;


--
-- Name: accounts id; Type: DEFAULT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.accounts ALTER COLUMN id SET DEFAULT nextval('public.accounts_id_seq'::regclass);


--
-- Name: announcement_reads id; Type: DEFAULT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.announcement_reads ALTER COLUMN id SET DEFAULT nextval('public.announcement_reads_id_seq'::regclass);


--
-- Name: announcements id; Type: DEFAULT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.announcements ALTER COLUMN id SET DEFAULT nextval('public.announcements_id_seq'::regclass);


--
-- Name: api_keys id; Type: DEFAULT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.api_keys ALTER COLUMN id SET DEFAULT nextval('public.api_keys_id_seq'::regclass);


--
-- Name: billing_usage_entries id; Type: DEFAULT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.billing_usage_entries ALTER COLUMN id SET DEFAULT nextval('public.billing_usage_entries_id_seq'::regclass);


--
-- Name: error_passthrough_rules id; Type: DEFAULT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.error_passthrough_rules ALTER COLUMN id SET DEFAULT nextval('public.error_passthrough_rules_id_seq'::regclass);


--
-- Name: groups id; Type: DEFAULT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.groups ALTER COLUMN id SET DEFAULT nextval('public.groups_id_seq'::regclass);


--
-- Name: idempotency_records id; Type: DEFAULT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.idempotency_records ALTER COLUMN id SET DEFAULT nextval('public.idempotency_records_id_seq'::regclass);


--
-- Name: ops_alert_events id; Type: DEFAULT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.ops_alert_events ALTER COLUMN id SET DEFAULT nextval('public.ops_alert_events_id_seq'::regclass);


--
-- Name: ops_alert_rules id; Type: DEFAULT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.ops_alert_rules ALTER COLUMN id SET DEFAULT nextval('public.ops_alert_rules_id_seq'::regclass);


--
-- Name: ops_error_logs id; Type: DEFAULT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.ops_error_logs ALTER COLUMN id SET DEFAULT nextval('public.ops_error_logs_id_seq'::regclass);


--
-- Name: ops_metrics_daily id; Type: DEFAULT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.ops_metrics_daily ALTER COLUMN id SET DEFAULT nextval('public.ops_metrics_daily_id_seq'::regclass);


--
-- Name: ops_metrics_hourly id; Type: DEFAULT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.ops_metrics_hourly ALTER COLUMN id SET DEFAULT nextval('public.ops_metrics_hourly_id_seq'::regclass);


--
-- Name: ops_retry_attempts id; Type: DEFAULT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.ops_retry_attempts ALTER COLUMN id SET DEFAULT nextval('public.ops_retry_attempts_id_seq'::regclass);


--
-- Name: ops_system_log_cleanup_audits id; Type: DEFAULT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.ops_system_log_cleanup_audits ALTER COLUMN id SET DEFAULT nextval('public.ops_system_log_cleanup_audits_id_seq'::regclass);


--
-- Name: ops_system_logs id; Type: DEFAULT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.ops_system_logs ALTER COLUMN id SET DEFAULT nextval('public.ops_system_logs_id_seq'::regclass);


--
-- Name: ops_system_metrics id; Type: DEFAULT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.ops_system_metrics ALTER COLUMN id SET DEFAULT nextval('public.ops_system_metrics_id_seq'::regclass);


--
-- Name: orphan_allowed_groups_audit id; Type: DEFAULT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.orphan_allowed_groups_audit ALTER COLUMN id SET DEFAULT nextval('public.orphan_allowed_groups_audit_id_seq'::regclass);


--
-- Name: promo_code_usages id; Type: DEFAULT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.promo_code_usages ALTER COLUMN id SET DEFAULT nextval('public.promo_code_usages_id_seq'::regclass);


--
-- Name: promo_codes id; Type: DEFAULT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.promo_codes ALTER COLUMN id SET DEFAULT nextval('public.promo_codes_id_seq'::regclass);


--
-- Name: proxies id; Type: DEFAULT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.proxies ALTER COLUMN id SET DEFAULT nextval('public.proxies_id_seq'::regclass);


--
-- Name: redeem_codes id; Type: DEFAULT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.redeem_codes ALTER COLUMN id SET DEFAULT nextval('public.redeem_codes_id_seq'::regclass);


--
-- Name: scheduler_outbox id; Type: DEFAULT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.scheduler_outbox ALTER COLUMN id SET DEFAULT nextval('public.scheduler_outbox_id_seq'::regclass);


--
-- Name: security_secrets id; Type: DEFAULT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.security_secrets ALTER COLUMN id SET DEFAULT nextval('public.security_secrets_id_seq'::regclass);


--
-- Name: settings id; Type: DEFAULT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.settings ALTER COLUMN id SET DEFAULT nextval('public.settings_id_seq'::regclass);


--
-- Name: usage_cleanup_tasks id; Type: DEFAULT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.usage_cleanup_tasks ALTER COLUMN id SET DEFAULT nextval('public.usage_cleanup_tasks_id_seq'::regclass);


--
-- Name: usage_logs id; Type: DEFAULT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.usage_logs ALTER COLUMN id SET DEFAULT nextval('public.usage_logs_id_seq'::regclass);


--
-- Name: user_attribute_definitions id; Type: DEFAULT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.user_attribute_definitions ALTER COLUMN id SET DEFAULT nextval('public.user_attribute_definitions_id_seq'::regclass);


--
-- Name: user_attribute_values id; Type: DEFAULT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.user_attribute_values ALTER COLUMN id SET DEFAULT nextval('public.user_attribute_values_id_seq'::regclass);


--
-- Name: user_subscriptions id; Type: DEFAULT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.user_subscriptions ALTER COLUMN id SET DEFAULT nextval('public.user_subscriptions_id_seq'::regclass);


--
-- Name: users id; Type: DEFAULT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.users ALTER COLUMN id SET DEFAULT nextval('public.users_id_seq'::regclass);


--
-- Data for Name: account_groups; Type: TABLE DATA; Schema: public; Owner: sub2api
--

COPY public.account_groups (account_id, group_id, priority, created_at) FROM stdin;
\.


--
-- Data for Name: accounts; Type: TABLE DATA; Schema: public; Owner: sub2api
--

COPY public.accounts (id, name, platform, type, credentials, extra, proxy_id, concurrency, priority, status, error_message, last_used_at, created_at, updated_at, deleted_at, schedulable, rate_limited_at, rate_limit_reset_at, overload_until, session_window_start, session_window_end, session_window_status, temp_unschedulable_until, temp_unschedulable_reason, notes, expires_at, auto_pause_on_expired, rate_multiplier) FROM stdin;
\.


--
-- Data for Name: announcement_reads; Type: TABLE DATA; Schema: public; Owner: sub2api
--

COPY public.announcement_reads (id, announcement_id, user_id, read_at, created_at) FROM stdin;
\.


--
-- Data for Name: announcements; Type: TABLE DATA; Schema: public; Owner: sub2api
--

COPY public.announcements (id, title, content, status, targeting, starts_at, ends_at, created_by, updated_by, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: api_keys; Type: TABLE DATA; Schema: public; Owner: sub2api
--

COPY public.api_keys (id, user_id, key, name, group_id, status, created_at, updated_at, deleted_at, ip_whitelist, ip_blacklist, quota, quota_used, expires_at, last_used_at) FROM stdin;
\.


--
-- Data for Name: atlas_schema_revisions; Type: TABLE DATA; Schema: public; Owner: sub2api
--

COPY public.atlas_schema_revisions (version, description, type, applied, total, executed_at, execution_time, error, error_stmt, hash, partial_hashes, operator_version) FROM stdin;
059_add_gemini31_pro_to_model_mapping	059_add_gemini31_pro_to_model_mapping	1	0	0	2026-02-25 10:51:17.924951+08	0	\N	\N	04e541c4600ccf3e54afae9506bb17db3335e02c0942958c120717147337e20f	\N	\N
\.


--
-- Data for Name: billing_usage_entries; Type: TABLE DATA; Schema: public; Owner: sub2api
--

COPY public.billing_usage_entries (id, usage_log_id, user_id, api_key_id, subscription_id, billing_type, applied, delta_usd, created_at) FROM stdin;
\.


--
-- Data for Name: error_passthrough_rules; Type: TABLE DATA; Schema: public; Owner: sub2api
--

COPY public.error_passthrough_rules (id, name, enabled, priority, error_codes, keywords, match_mode, platforms, passthrough_code, response_code, passthrough_body, custom_message, description, created_at, updated_at, skip_monitoring) FROM stdin;
\.


--
-- Data for Name: groups; Type: TABLE DATA; Schema: public; Owner: sub2api
--

COPY public.groups (id, name, description, rate_multiplier, is_exclusive, status, created_at, updated_at, deleted_at, platform, subscription_type, daily_limit_usd, weekly_limit_usd, monthly_limit_usd, default_validity_days, image_price_1k, image_price_2k, image_price_4k, claude_code_only, fallback_group_id, model_routing, model_routing_enabled, fallback_group_id_on_invalid_request, mcp_xml_inject, supported_model_scopes, sora_image_price_360, sora_image_price_540, sora_video_price_per_request, sora_video_price_per_request_hd, sort_order) FROM stdin;
1	default	Default group	1.0000	f	active	2026-02-25 10:51:18.123449+08	2026-02-25 10:51:18.123449+08	\N	anthropic	standard	\N	\N	\N	30	\N	\N	\N	f	\N	{}	f	\N	t	["claude", "gemini_text", "gemini_image"]	\N	\N	\N	\N	1
\.


--
-- Data for Name: idempotency_records; Type: TABLE DATA; Schema: public; Owner: sub2api
--

COPY public.idempotency_records (id, scope, idempotency_key_hash, request_fingerprint, status, response_status, response_body, error_reason, locked_until, expires_at, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: ops_alert_events; Type: TABLE DATA; Schema: public; Owner: sub2api
--

COPY public.ops_alert_events (id, rule_id, severity, status, title, description, metric_value, threshold_value, dimensions, fired_at, resolved_at, email_sent, created_at) FROM stdin;
\.


--
-- Data for Name: ops_alert_rules; Type: TABLE DATA; Schema: public; Owner: sub2api
--

COPY public.ops_alert_rules (id, name, description, enabled, severity, metric_type, operator, threshold, window_minutes, sustained_minutes, cooldown_minutes, filters, last_triggered_at, created_at, updated_at, notify_email) FROM stdin;
1	错误率过高	当错误率超过 5% 且持续 5 分钟时触发告警	t	P1	error_rate	>	5	5	5	20	\N	\N	2026-02-25 10:51:18.327435+08	2026-02-25 10:51:18.327435+08	t
2	成功率过低	当成功率低于 95% 且持续 5 分钟时触发告警（服务可用性下降）	t	P0	success_rate	<	95	5	5	15	\N	\N	2026-02-25 10:51:18.327435+08	2026-02-25 10:51:18.327435+08	t
3	P99延迟过高	当 P99 延迟超过 3000ms 且持续 10 分钟时触发告警	t	P2	p99_latency_ms	>	3000	5	10	30	\N	\N	2026-02-25 10:51:18.327435+08	2026-02-25 10:51:18.327435+08	t
4	P95延迟过高	当 P95 延迟超过 2000ms 且持续 10 分钟时触发告警	t	P2	p95_latency_ms	>	2000	5	10	30	\N	\N	2026-02-25 10:51:18.327435+08	2026-02-25 10:51:18.327435+08	t
5	CPU使用率过高	当 CPU 使用率超过 85% 且持续 10 分钟时触发告警	t	P2	cpu_usage_percent	>	85	5	10	30	\N	\N	2026-02-25 10:51:18.327435+08	2026-02-25 10:51:18.327435+08	t
6	内存使用率过高	当内存使用率超过 90% 且持续 10 分钟时触发告警（可能导致 OOM）	t	P1	memory_usage_percent	>	90	5	10	20	\N	\N	2026-02-25 10:51:18.327435+08	2026-02-25 10:51:18.327435+08	t
7	并发队列积压	当并发队列深度超过 100 且持续 5 分钟时触发告警（系统处理能力不足）	t	P1	concurrency_queue_depth	>	100	5	5	20	\N	\N	2026-02-25 10:51:18.327435+08	2026-02-25 10:51:18.327435+08	t
8	错误率极高	当错误率超过 20% 且持续 1 分钟时触发告警（服务严重异常）	t	P0	error_rate	>	20	1	1	15	\N	\N	2026-02-25 10:51:18.327435+08	2026-02-25 10:51:18.327435+08	t
\.


--
-- Data for Name: ops_error_logs; Type: TABLE DATA; Schema: public; Owner: sub2api
--

COPY public.ops_error_logs (id, request_id, client_request_id, user_id, api_key_id, account_id, group_id, client_ip, platform, model, request_path, stream, user_agent, error_phase, error_type, severity, status_code, is_business_limited, error_message, error_body, error_source, error_owner, account_status, upstream_status_code, upstream_error_message, upstream_error_detail, provider_error_code, provider_error_type, network_error_type, retry_after_seconds, duration_ms, time_to_first_token_ms, auth_latency_ms, routing_latency_ms, upstream_latency_ms, response_latency_ms, request_body, request_headers, request_body_truncated, request_body_bytes, is_retryable, retry_count, created_at, upstream_errors, is_count_tokens, resolved, resolved_at, resolved_by_user_id, resolved_retry_id) FROM stdin;
\.


--
-- Data for Name: ops_job_heartbeats; Type: TABLE DATA; Schema: public; Owner: sub2api
--

COPY public.ops_job_heartbeats (job_name, last_run_at, last_success_at, last_error_at, last_error, last_duration_ms, updated_at, last_result) FROM stdin;
ops_preaggregation_hourly	2026-02-25 13:31:39.779397+08	2026-02-25 13:31:39.859014+08	\N	\N	79	2026-02-25 13:31:39.859521+08	window=2026-01-26T05:00:00Z..2026-02-25T05:00:00Z
ops_metrics_collector	2026-02-25 13:38:41.333016+08	2026-02-25 13:38:41.340836+08	\N	\N	7	2026-02-25 13:38:41.341236+08	\N
ops_alert_evaluator	2026-02-25 13:38:42.888852+08	2026-02-25 13:38:42.911972+08	\N	\N	23	2026-02-25 13:38:42.912157+08	rules=8 enabled=8 evaluated=2 created=0 resolved=0 emails_sent=0
ops_preaggregation_daily	2026-02-25 12:51:39.720108+08	2026-02-25 12:51:39.732115+08	\N	\N	12	2026-02-25 12:51:39.73264+08	window=2026-01-26T00:00:00Z..2026-02-25T00:00:00Z
\.


--
-- Data for Name: ops_metrics_daily; Type: TABLE DATA; Schema: public; Owner: sub2api
--

COPY public.ops_metrics_daily (id, bucket_date, platform, group_id, success_count, error_count_total, business_limited_count, error_count_sla, upstream_error_count_excl_429_529, upstream_429_count, upstream_529_count, token_consumed, duration_p50_ms, duration_p90_ms, duration_p95_ms, duration_p99_ms, ttft_p50_ms, ttft_p90_ms, ttft_p95_ms, ttft_p99_ms, computed_at, created_at, duration_avg_ms, duration_max_ms, ttft_avg_ms, ttft_max_ms) FROM stdin;
\.


--
-- Data for Name: ops_metrics_hourly; Type: TABLE DATA; Schema: public; Owner: sub2api
--

COPY public.ops_metrics_hourly (id, bucket_start, platform, group_id, success_count, error_count_total, business_limited_count, error_count_sla, upstream_error_count_excl_429_529, upstream_429_count, upstream_529_count, token_consumed, duration_p50_ms, duration_p90_ms, duration_p95_ms, duration_p99_ms, ttft_p50_ms, ttft_p90_ms, ttft_p95_ms, ttft_p99_ms, computed_at, created_at, duration_avg_ms, duration_max_ms, ttft_avg_ms, ttft_max_ms) FROM stdin;
\.


--
-- Data for Name: ops_retry_attempts; Type: TABLE DATA; Schema: public; Owner: sub2api
--

COPY public.ops_retry_attempts (id, created_at, requested_by_user_id, source_error_id, mode, pinned_account_id, status, started_at, finished_at, duration_ms, result_request_id, result_error_id, result_usage_request_id, error_message, success, http_status_code, upstream_request_id, used_account_id, response_preview, response_truncated) FROM stdin;
\.


--
-- Data for Name: ops_system_log_cleanup_audits; Type: TABLE DATA; Schema: public; Owner: sub2api
--

COPY public.ops_system_log_cleanup_audits (id, created_at, operator_id, conditions, deleted_rows) FROM stdin;
\.


--
-- Data for Name: ops_system_logs; Type: TABLE DATA; Schema: public; Owner: sub2api
--

COPY public.ops_system_logs (id, created_at, level, component, message, request_id, client_request_id, user_id, account_id, platform, model, extra) FROM stdin;
1	2026-02-25 10:51:19.663113+08	warn	stdlog	Warning: server.trusted_proxies is empty in release mode; client IP trust chain is disabled	\N	\N	\N	\N	\N	\N	{"env": "production", "service": "sub2api", "legacy_stdlog": true}
2	2026-02-25 10:51:19.66316+08	warn	stdlog	Warning: CORS allowed_origins not configured; cross-origin requests will be rejected.	\N	\N	\N	\N	\N	\N	{"env": "production", "service": "sub2api", "legacy_stdlog": true}
3	2026-02-25 10:51:40.896525+08	info	http.access	http request completed	a9ec47d9-83bb-4f5c-aa0a-fc514127e62a	\N	\N	\N	\N	\N	{"env": "production", "path": "/", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 1, "request_id": "a9ec47d9-83bb-4f5c-aa0a-fc514127e62a", "status_code": 200, "completed_at": "2026-02-25T10:51:40.896501988+08:00", "client_request_id": ""}
4	2026-02-25 10:51:40.921852+08	info	http.access	http request completed	ec82cef4-de56-45ea-be64-c43e9cd99e2e	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/index-CrU_eI8r.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "ec82cef4-de56-45ea-be64-c43e9cd99e2e", "status_code": 200, "completed_at": "2026-02-25T10:51:40.921812441+08:00", "client_request_id": ""}
5	2026-02-25 10:51:40.922494+08	info	http.access	http request completed	4094733c-51ba-4108-b6e5-8025df79963e	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/vendor-vue-4WNFgugS.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 1, "request_id": "4094733c-51ba-4108-b6e5-8025df79963e", "status_code": 200, "completed_at": "2026-02-25T10:51:40.922470437+08:00", "client_request_id": ""}
6	2026-02-25 10:51:40.922949+08	info	http.access	http request completed	b0baeef1-f006-49fb-8781-e3e82435962b	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/vendor-misc-NmuJm1mp.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "b0baeef1-f006-49fb-8781-e3e82435962b", "status_code": 200, "completed_at": "2026-02-25T10:51:40.922931334+08:00", "client_request_id": ""}
7	2026-02-25 10:51:40.924031+08	info	http.access	http request completed	9ee78ab6-7ffb-4d4e-83db-4cba587074a9	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/vendor-i18n-CF5oKjnm.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "9ee78ab6-7ffb-4d4e-83db-4cba587074a9", "status_code": 200, "completed_at": "2026-02-25T10:51:40.924008828+08:00", "client_request_id": ""}
8	2026-02-25 10:51:40.92481+08	info	http.access	http request completed	cdd84904-3ae5-47b0-9272-3aab243621da	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/vendor-misc-DB0Q8XAf.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "cdd84904-3ae5-47b0-9272-3aab243621da", "status_code": 200, "completed_at": "2026-02-25T10:51:40.924795923+08:00", "client_request_id": ""}
9	2026-02-25 10:51:40.925851+08	info	http.access	http request completed	a755d1f8-813d-4c68-bb99-0dc931c6919b	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/index-Dji9Snxu.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "a755d1f8-813d-4c68-bb99-0dc931c6919b", "status_code": 200, "completed_at": "2026-02-25T10:51:40.925831617+08:00", "client_request_id": ""}
10	2026-02-25 10:51:41.049813+08	info	http.access	http request completed	75046f80-284a-4dce-af34-83731cc97c32	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/zh-joyDK6VH.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "75046f80-284a-4dce-af34-83731cc97c32", "status_code": 200, "completed_at": "2026-02-25T10:51:41.049795696+08:00", "client_request_id": ""}
11	2026-02-25 10:51:41.070362+08	info	http.access	http request completed	356cebbd-7121-41a7-a424-f8a9bc112904	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/LocaleSwitcher-CJSwBRWY.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "356cebbd-7121-41a7-a424-f8a9bc112904", "status_code": 200, "completed_at": "2026-02-25T10:51:41.070283277+08:00", "client_request_id": ""}
12	2026-02-25 10:51:41.070404+08	info	http.access	http request completed	343bef7d-9096-4cea-9a3c-5471d1339109	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/HomeView-pQUgJRYo.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "343bef7d-9096-4cea-9a3c-5471d1339109", "status_code": 200, "completed_at": "2026-02-25T10:51:41.070379276+08:00", "client_request_id": ""}
13	2026-02-25 10:51:41.070516+08	info	http.access	http request completed	0b5782b7-2b87-4bad-a15c-7c35b034ee16	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/LocaleSwitcher-CjvPxOhx.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "0b5782b7-2b87-4bad-a15c-7c35b034ee16", "status_code": 200, "completed_at": "2026-02-25T10:51:41.070496775+08:00", "client_request_id": ""}
14	2026-02-25 10:51:41.070609+08	info	http.access	http request completed	d02c2c93-4070-4cf1-9dfb-3b47430bd8f8	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/HomeView-Dww6Lv6Y.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "d02c2c93-4070-4cf1-9dfb-3b47430bd8f8", "status_code": 200, "completed_at": "2026-02-25T10:51:41.070599375+08:00", "client_request_id": ""}
15	2026-02-25 10:51:41.071253+08	info	http.access	http request completed	ffc4fea8-169a-435e-aebf-878c7ff28733	\N	\N	\N	\N	\N	{"env": "production", "path": "/logo.png", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "ffc4fea8-169a-435e-aebf-878c7ff28733", "status_code": 200, "completed_at": "2026-02-25T10:51:41.071227171+08:00", "client_request_id": ""}
16	2026-02-25 10:51:41.189501+08	info	http.access	http request completed	32bad1fe-dec2-429a-8ceb-78d2743661a2	\N	\N	\N	\N	\N	{"env": "production", "path": "/logo.png", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "32bad1fe-dec2-429a-8ceb-78d2743661a2", "status_code": 200, "completed_at": "2026-02-25T10:51:41.189488583+08:00", "client_request_id": ""}
17	2026-02-25 10:51:41.202547+08	info	http.access	http request completed	dcef004e-cd4a-4d43-8270-9cfe797c16a3	\N	\N	\N	\N	\N	{"env": "production", "path": "/logo.png", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "dcef004e-cd4a-4d43-8270-9cfe797c16a3", "status_code": 200, "completed_at": "2026-02-25T10:51:41.202515407+08:00", "client_request_id": ""}
18	2026-02-25 10:51:43.115372+08	info	http.access	http request completed	80243105-438d-4b88-b020-b8ed91a62c9d	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/AuthLayout-D_5JJD4j.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "80243105-438d-4b88-b020-b8ed91a62c9d", "status_code": 200, "completed_at": "2026-02-25T10:51:43.115358772+08:00", "client_request_id": ""}
19	2026-02-25 10:51:43.11552+08	info	http.access	http request completed	c89c78e1-2abb-45a8-88dc-44e344f94a22	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/LoginView-Dm2m7DcW.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "c89c78e1-2abb-45a8-88dc-44e344f94a22", "status_code": 200, "completed_at": "2026-02-25T10:51:43.115508471+08:00", "client_request_id": ""}
20	2026-02-25 10:51:43.115685+08	info	http.access	http request completed	eaf9522b-876b-4d40-8413-55d752bb81eb	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/AuthLayout-BLY8cBK0.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "eaf9522b-876b-4d40-8413-55d752bb81eb", "status_code": 200, "completed_at": "2026-02-25T10:51:43.11567637+08:00", "client_request_id": ""}
21	2026-02-25 10:51:43.1157+08	info	http.access	http request completed	d7299d2b-c389-42e6-9f87-111b4c17cb1f	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/TurnstileWidget-CtZXX_iR.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "d7299d2b-c389-42e6-9f87-111b4c17cb1f", "status_code": 200, "completed_at": "2026-02-25T10:51:43.11569367+08:00", "client_request_id": ""}
22	2026-02-25 10:51:43.115883+08	info	http.access	http request completed	12d7620d-22c5-40b8-bab5-1626eadc246d	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/LinuxDoOAuthSection.vue_vue_type_script_setup_true_lang-DJujUfeo.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "12d7620d-22c5-40b8-bab5-1626eadc246d", "status_code": 200, "completed_at": "2026-02-25T10:51:43.115876869+08:00", "client_request_id": ""}
23	2026-02-25 10:51:43.115919+08	info	http.access	http request completed	18962f7b-3a47-4fb3-bbf1-c0cfe43e9105	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/TurnstileWidget-9t9fJkOj.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "18962f7b-3a47-4fb3-bbf1-c0cfe43e9105", "status_code": 200, "completed_at": "2026-02-25T10:51:43.115908169+08:00", "client_request_id": ""}
24	2026-02-25 10:51:43.117005+08	info	http.access	http request completed	5ff8ec5f-f48d-4b27-a159-97f19a389562	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/LoginView-CM0iaiMq.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "5ff8ec5f-f48d-4b27-a159-97f19a389562", "status_code": 200, "completed_at": "2026-02-25T10:51:43.116995963+08:00", "client_request_id": ""}
25	2026-02-25 10:51:43.117276+08	info	http.access	http request completed	68ea7741-9909-4e5a-8815-7f48f52aa799	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/AppHeader-NeOcFzPI.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "68ea7741-9909-4e5a-8815-7f48f52aa799", "status_code": 200, "completed_at": "2026-02-25T10:51:43.117260061+08:00", "client_request_id": ""}
26	2026-02-25 10:51:43.134106+08	info	http.access	http request completed	53a02bd3-7bee-46cd-9eba-2c8a57b702f6	\N	\N	\N	\N	\N	{"env": "production", "path": "/logo.png", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "53a02bd3-7bee-46cd-9eba-2c8a57b702f6", "status_code": 200, "completed_at": "2026-02-25T10:51:43.134090763+08:00", "client_request_id": ""}
27	2026-02-25 10:51:43.134496+08	info	http.access	http request completed	4e8c1e47-6428-4c18-855c-0a59d08c8948	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/settings/public", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "4e8c1e47-6428-4c18-855c-0a59d08c8948", "status_code": 200, "completed_at": "2026-02-25T10:51:43.134481861+08:00", "client_request_id": ""}
28	2026-02-25 10:52:28.985986+08	info	http.access	http request completed	b05c0ca2-4438-4b44-ad7b-3016a47eceac	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/login", "method": "POST", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 55, "request_id": "b05c0ca2-4438-4b44-ad7b-3016a47eceac", "status_code": 200, "completed_at": "2026-02-25T10:52:28.985966574+08:00", "client_request_id": ""}
29	2026-02-25 10:52:28.993736+08	info	http.access	http request completed	0139a055-a3df-41c0-b704-d5ddda6959ba	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/usage-BlWL46gW.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "0139a055-a3df-41c0-b704-d5ddda6959ba", "status_code": 200, "completed_at": "2026-02-25T10:52:28.993724128+08:00", "client_request_id": ""}
30	2026-02-25 10:52:28.993883+08	info	http.access	http request completed	79e3a081-119a-4e9d-a709-54ea9dd90be3	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/DashboardView-DVWIfxM4.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "79e3a081-119a-4e9d-a709-54ea9dd90be3", "status_code": 200, "completed_at": "2026-02-25T10:52:28.993868527+08:00", "client_request_id": ""}
31	2026-02-25 10:52:28.993925+08	info	http.access	http request completed	ba7e82bd-dee1-4f78-a649-0d96a4852ddc	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/LoadingSpinner-DT-rtrW_.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "ba7e82bd-dee1-4f78-a649-0d96a4852ddc", "status_code": 200, "completed_at": "2026-02-25T10:52:28.993904727+08:00", "client_request_id": ""}
32	2026-02-25 10:52:28.993946+08	info	http.access	http request completed	bb4f494e-7427-4590-97fc-e4a792f4e7c9	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/subscriptions/active", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "bb4f494e-7427-4590-97fc-e4a792f4e7c9", "status_code": 200, "completed_at": "2026-02-25T10:52:28.993932727+08:00", "client_request_id": ""}
745	2026-02-25 13:31:41.589861+08	error	service.pricing	[Pricing] Failed to save hash: open data/model_pricing.sha256: permission denied	\N	\N	\N	\N	\N	\N	{"env": "production", "service": "sub2api", "component": "service.pricing", "legacy_printf": true}
33	2026-02-25 10:52:28.993953+08	info	http.access	http request completed	9f5975c1-2520-45b1-b8a9-d1499243ff94	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/LoadingSpinner-CyStGumC.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "9f5975c1-2520-45b1-b8a9-d1499243ff94", "status_code": 200, "completed_at": "2026-02-25T10:52:28.993939327+08:00", "client_request_id": ""}
34	2026-02-25 10:52:28.994022+08	info	http.access	http request completed	6bf22796-8ab1-4a4c-8e05-6038aa6b7f61	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/AppLayout.vue_vue_type_script_setup_true_lang-CKTAlA0-.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "6bf22796-8ab1-4a4c-8e05-6038aa6b7f61", "status_code": 200, "completed_at": "2026-02-25T10:52:28.994002927+08:00", "client_request_id": ""}
35	2026-02-25 10:52:28.995905+08	info	http.access	http request completed	80a854a8-3510-48a5-b54a-e1566a71371c	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/DateRangePicker-CFGGkPM1.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "80a854a8-3510-48a5-b54a-e1566a71371c", "status_code": 200, "completed_at": "2026-02-25T10:52:28.995896915+08:00", "client_request_id": ""}
36	2026-02-25 10:52:28.99609+08	info	http.access	http request completed	4b253958-6d9d-4d77-a25a-c63980452376	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/DateRangePicker-4QcPOZ3x.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "4b253958-6d9d-4d77-a25a-c63980452376", "status_code": 200, "completed_at": "2026-02-25T10:52:28.996071014+08:00", "client_request_id": ""}
37	2026-02-25 10:52:28.996155+08	info	http.access	http request completed	c8e8e108-f4cf-47f2-814d-3833d9df04fa	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/Select-7fPaeC0I.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "c8e8e108-f4cf-47f2-814d-3833d9df04fa", "status_code": 200, "completed_at": "2026-02-25T10:52:28.996140214+08:00", "client_request_id": ""}
38	2026-02-25 10:52:28.996292+08	info	http.access	http request completed	43f479e2-f1d0-4d3e-ae4c-bb7affeb6dfc	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/Select-M2m3gzLX.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "43f479e2-f1d0-4d3e-ae4c-bb7affeb6dfc", "status_code": 200, "completed_at": "2026-02-25T10:52:28.996261413+08:00", "client_request_id": ""}
39	2026-02-25 10:52:28.996755+08	info	http.access	http request completed	5d93af9b-6299-431c-869c-68aa53078a8f	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/vendor-chart-BqAhThnj.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "5d93af9b-6299-431c-869c-68aa53078a8f", "status_code": 200, "completed_at": "2026-02-25T10:52:28.99674101+08:00", "client_request_id": ""}
40	2026-02-25 10:52:28.999853+08	info	http.access	http request completed	5cb478be-c2cd-4151-9d48-22568897f7b7	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/TokenUsageTrend.vue_vue_type_script_setup_true_lang-DnDbESHW.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "5cb478be-c2cd-4151-9d48-22568897f7b7", "status_code": 200, "completed_at": "2026-02-25T10:52:28.999836992+08:00", "client_request_id": ""}
41	2026-02-25 10:52:29.001122+08	info	http.access	http request completed	e1899b9c-7ce9-4fa1-af73-14cfd8653494	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/EmptyState.vue_vue_type_script_setup_true_lang-BuIi38rv.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "e1899b9c-7ce9-4fa1-af73-14cfd8653494", "status_code": 200, "completed_at": "2026-02-25T10:52:29.001102485+08:00", "client_request_id": ""}
42	2026-02-25 10:52:29.053878+08	info	http.access	http request completed	d20e7b86-25cf-4e26-a519-201eeaf86639	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/settings", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "d20e7b86-25cf-4e26-a519-201eeaf86639", "status_code": 200, "completed_at": "2026-02-25T10:52:29.053839373+08:00", "client_request_id": ""}
43	2026-02-25 10:52:29.057096+08	info	http.access	http request completed	85efe352-776b-49a2-afdf-f31f8f10f11d	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 6, "request_id": "85efe352-776b-49a2-afdf-f31f8f10f11d", "status_code": 200, "completed_at": "2026-02-25T10:52:29.057057854+08:00", "client_request_id": ""}
44	2026-02-25 10:52:29.060956+08	info	http.access	http request completed	67dd8be8-c068-489a-a84a-146992e8a4ce	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/KeysView-CCSOZ5fG.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "67dd8be8-c068-489a-a84a-146992e8a4ce", "status_code": 200, "completed_at": "2026-02-25T10:52:29.060931331+08:00", "client_request_id": ""}
45	2026-02-25 10:52:29.061098+08	info	http.access	http request completed	caa0b45f-5138-4fc7-ba52-0d6a204aabee	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "caa0b45f-5138-4fc7-ba52-0d6a204aabee", "status_code": 200, "completed_at": "2026-02-25T10:52:29.061082031+08:00", "client_request_id": ""}
46	2026-02-25 10:52:29.062797+08	info	http.access	http request completed	6079ce88-ffd3-4301-a966-17c61c103259	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage/dashboard/trend", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 11, "request_id": "6079ce88-ffd3-4301-a966-17c61c103259", "status_code": 200, "completed_at": "2026-02-25T10:52:29.062764521+08:00", "client_request_id": ""}
47	2026-02-25 10:52:29.063436+08	info	http.access	http request completed	3e824781-1e38-41b7-a0e2-faa2860e68db	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/TablePageLayout-eKTo0RsV.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "3e824781-1e38-41b7-a0e2-faa2860e68db", "status_code": 200, "completed_at": "2026-02-25T10:52:29.063409617+08:00", "client_request_id": ""}
48	2026-02-25 10:52:29.06351+08	info	http.access	http request completed	1e742de8-2e83-40fc-a203-d11c1a216541	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage/dashboard/models", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 11, "request_id": "1e742de8-2e83-40fc-a203-d11c1a216541", "status_code": 200, "completed_at": "2026-02-25T10:52:29.063495016+08:00", "client_request_id": ""}
49	2026-02-25 10:52:29.063531+08	info	http.access	http request completed	e14d788d-8a5a-455a-88c2-eacacb035539	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/DataTable-wk4w1kiu.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "e14d788d-8a5a-455a-88c2-eacacb035539", "status_code": 200, "completed_at": "2026-02-25T10:52:29.063521416+08:00", "client_request_id": ""}
50	2026-02-25 10:52:29.067212+08	info	http.access	http request completed	173a502b-570d-4d54-a7a5-198214d34ed3	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/announcements", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 16, "request_id": "173a502b-570d-4d54-a7a5-198214d34ed3", "status_code": 200, "completed_at": "2026-02-25T10:52:29.067178394+08:00", "client_request_id": ""}
51	2026-02-25 10:52:29.067426+08	info	http.access	http request completed	0f3fc9d3-4e2e-44c9-b3d6-cb4da9cc7117	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/Pagination-DtcDDVEA.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "0f3fc9d3-4e2e-44c9-b3d6-cb4da9cc7117", "status_code": 200, "completed_at": "2026-02-25T10:52:29.067413993+08:00", "client_request_id": ""}
52	2026-02-25 10:52:29.067763+08	info	http.access	http request completed	019de1d7-8e9d-4230-922f-9e343e1d9380	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/useClipboard-CYH4PDKz.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "019de1d7-8e9d-4230-922f-9e343e1d9380", "status_code": 200, "completed_at": "2026-02-25T10:52:29.067746491+08:00", "client_request_id": ""}
53	2026-02-25 10:52:29.067757+08	info	http.access	http request completed	c43d8f24-f520-4910-8a38-783c2604a4f6	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/keys-_v9ZnNui.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "c43d8f24-f520-4910-8a38-783c2604a4f6", "status_code": 200, "completed_at": "2026-02-25T10:52:29.067748791+08:00", "client_request_id": ""}
54	2026-02-25 10:52:29.067864+08	info	http.access	http request completed	9d00502c-0196-4128-bd4d-2fc6115d71ff	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/TablePageLayout-BIThKX5Z.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "9d00502c-0196-4128-bd4d-2fc6115d71ff", "status_code": 200, "completed_at": "2026-02-25T10:52:29.06785629+08:00", "client_request_id": ""}
55	2026-02-25 10:52:29.071662+08	info	http.access	http request completed	3d17af8e-fc48-4686-9ed0-eeecdb2ac4fd	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/GroupBadge.vue_vue_type_script_setup_true_lang-Cej1HtUK.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "3d17af8e-fc48-4686-9ed0-eeecdb2ac4fd", "status_code": 200, "completed_at": "2026-02-25T10:52:29.071654068+08:00", "client_request_id": ""}
56	2026-02-25 10:52:29.071699+08	info	http.access	http request completed	4fc6ef30-8eeb-4a90-9bb1-0770a89be39f	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/PlatformIcon.vue_vue_type_script_setup_true_lang-DDJ5Ol8Z.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "4fc6ef30-8eeb-4a90-9bb1-0770a89be39f", "status_code": 200, "completed_at": "2026-02-25T10:52:29.071689468+08:00", "client_request_id": ""}
57	2026-02-25 10:52:29.071661+08	info	http.access	http request completed	311612dc-ecbd-4c41-a9c5-7e69ce80423e	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/DataTable-BSDXutJh.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "311612dc-ecbd-4c41-a9c5-7e69ce80423e", "status_code": 200, "completed_at": "2026-02-25T10:52:29.071633568+08:00", "client_request_id": ""}
58	2026-02-25 10:52:29.071674+08	info	http.access	http request completed	8e5a2fba-3757-4327-bade-1a0a673734b3	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/Pagination-Cy120BZx.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "8e5a2fba-3757-4327-bade-1a0a673734b3", "status_code": 200, "completed_at": "2026-02-25T10:52:29.071654168+08:00", "client_request_id": ""}
59	2026-02-25 10:52:29.071655+08	info	http.access	http request completed	71695039-d49b-45fa-9716-7ba62b83f7ac	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/ConfirmDialog.vue_vue_type_script_setup_true_lang-Brt6MSpz.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "71695039-d49b-45fa-9716-7ba62b83f7ac", "status_code": 200, "completed_at": "2026-02-25T10:52:29.071645168+08:00", "client_request_id": ""}
60	2026-02-25 10:52:29.075091+08	info	http.access	http request completed	171fa1f0-c2fd-4afa-9725-cb03387518db	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/GroupOptionItem.vue_vue_type_script_setup_true_lang-DJgQlkUJ.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "171fa1f0-c2fd-4afa-9725-cb03387518db", "status_code": 200, "completed_at": "2026-02-25T10:52:29.075067448+08:00", "client_request_id": ""}
61	2026-02-25 10:52:29.075514+08	info	http.access	http request completed	40be2ca6-b157-4248-9352-997dbb967096	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/UsageView-WokokQ3Q.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "40be2ca6-b157-4248-9352-997dbb967096", "status_code": 200, "completed_at": "2026-02-25T10:52:29.075486845+08:00", "client_request_id": ""}
62	2026-02-25 10:52:29.086101+08	info	http.access	http request completed	6376178e-9fdd-43a9-9f3b-7dc9a320988b	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage/dashboard/stats", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 10, "request_id": "6376178e-9fdd-43a9-9f3b-7dc9a320988b", "status_code": 200, "completed_at": "2026-02-25T10:52:29.086077383+08:00", "client_request_id": ""}
63	2026-02-25 10:52:29.326142+08	info	http.access	http request completed	212261a5-3216-4739-bfe9-737fc6f3934c	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/system/check-updates", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 275, "request_id": "212261a5-3216-4739-bfe9-737fc6f3934c", "status_code": 200, "completed_at": "2026-02-25T10:52:29.326119465+08:00", "client_request_id": ""}
64	2026-02-25 10:52:38.712913+08	info	http.access	http request completed	5dba2ee1-e381-48f6-9e91-dc1b2e56fb94	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/GroupSelector.vue_vue_type_script_setup_true_lang-CcNVQhCX.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "5dba2ee1-e381-48f6-9e91-dc1b2e56fb94", "status_code": 200, "completed_at": "2026-02-25T10:52:38.712899236+08:00", "client_request_id": ""}
65	2026-02-25 10:52:38.71299+08	info	http.access	http request completed	6d270814-1c39-4f7a-ab04-729cfa99d744	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/stableObjectKey-DullU5Fx.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "6d270814-1c39-4f7a-ab04-729cfa99d744", "status_code": 200, "completed_at": "2026-02-25T10:52:38.712970835+08:00", "client_request_id": ""}
66	2026-02-25 10:52:38.713077+08	info	http.access	http request completed	78db4972-e62e-46fa-8e2c-f1630f41677e	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/ModelDistributionChart.vue_vue_type_script_setup_true_lang-C4GZUv6g.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "78db4972-e62e-46fa-8e2c-f1630f41677e", "status_code": 200, "completed_at": "2026-02-25T10:52:38.713064135+08:00", "client_request_id": ""}
67	2026-02-25 10:52:38.713302+08	info	http.access	http request completed	35f01d8c-8fb1-4ada-878c-4d4a514b992c	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/PlatformTypeBadge.vue_vue_type_script_setup_true_lang-C0GL-GYg.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "35f01d8c-8fb1-4ada-878c-4d4a514b992c", "status_code": 200, "completed_at": "2026-02-25T10:52:38.713291933+08:00", "client_request_id": ""}
68	2026-02-25 10:52:38.713706+08	info	http.access	http request completed	6c1a582c-2bf3-4552-ba20-d788ed0818d9	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/AccountsView-HVqLN203.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "6c1a582c-2bf3-4552-ba20-d788ed0818d9", "status_code": 200, "completed_at": "2026-02-25T10:52:38.713671231+08:00", "client_request_id": ""}
69	2026-02-25 10:52:38.713795+08	info	http.access	http request completed	673750b4-bb1a-4940-a226-d7a40ad46e72	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/vendor-ui-CAt8eLho.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "673750b4-bb1a-4940-a226-d7a40ad46e72", "status_code": 200, "completed_at": "2026-02-25T10:52:38.71376803+08:00", "client_request_id": ""}
70	2026-02-25 10:52:38.715213+08	info	http.access	http request completed	168241c1-dde9-4bc8-8281-1131f763e109	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/AccountsView-D1GA-FAQ.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "168241c1-dde9-4bc8-8281-1131f763e109", "status_code": 200, "completed_at": "2026-02-25T10:52:38.715198721+08:00", "client_request_id": ""}
71	2026-02-25 10:52:38.792554+08	info	http.access	http request completed	74798e6a-72cd-4df1-a036-692fe734e83b	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/proxies/all", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "74798e6a-72cd-4df1-a036-692fe734e83b", "status_code": 200, "completed_at": "2026-02-25T10:52:38.792538222+08:00", "client_request_id": ""}
72	2026-02-25 10:52:38.794639+08	info	http.access	http request completed	54c1a60c-1712-48d5-8928-fe3ad764f588	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/accounts", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 5, "request_id": "54c1a60c-1712-48d5-8928-fe3ad764f588", "status_code": 200, "completed_at": "2026-02-25T10:52:38.794616608+08:00", "client_request_id": ""}
73	2026-02-25 10:52:38.795222+08	info	http.access	http request completed	54609970-6cbe-4546-82ef-ecf3c0762a89	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/groups/all", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 5, "request_id": "54609970-6cbe-4546-82ef-ecf3c0762a89", "status_code": 200, "completed_at": "2026-02-25T10:52:38.795203805+08:00", "client_request_id": ""}
74	2026-02-25 10:52:38.796615+08	info	http.access	http request completed	db88faed-e307-49c9-ba4f-13cacafe827f	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/announcements", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 7, "request_id": "db88faed-e307-49c9-ba4f-13cacafe827f", "status_code": 200, "completed_at": "2026-02-25T10:52:38.796602596+08:00", "client_request_id": ""}
75	2026-02-25 10:52:38.822834+08	info	http.access	http request completed	af067ee8-3cdc-43a9-919d-b7c743ac5151	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/UsersView-qOd5hN3-.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "af067ee8-3cdc-43a9-919d-b7c743ac5151", "status_code": 200, "completed_at": "2026-02-25T10:52:38.822812526+08:00", "client_request_id": ""}
76	2026-02-25 10:52:38.822827+08	info	http.access	http request completed	58c7f257-30da-46f5-9b9d-5be16be51cd2	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/DashboardView-Ai2Uq9NG.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "58c7f257-30da-46f5-9b9d-5be16be51cd2", "status_code": 200, "completed_at": "2026-02-25T10:52:38.822809526+08:00", "client_request_id": ""}
77	2026-02-25 10:52:38.822949+08	info	http.access	http request completed	4cf44589-3a60-4a1e-97d4-9b089e8b2428	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/UsersView-D-m7HAka.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "4cf44589-3a60-4a1e-97d4-9b089e8b2428", "status_code": 200, "completed_at": "2026-02-25T10:52:38.822935626+08:00", "client_request_id": ""}
78	2026-02-25 10:52:39.982041+08	info	http.access	http request completed	0cf10599-477d-481b-8839-0fd9098349b4	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/Toggle.vue_vue_type_script_setup_true_lang-B0FKZlYT.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "0cf10599-477d-481b-8839-0fd9098349b4", "status_code": 200, "completed_at": "2026-02-25T10:52:39.982025836+08:00", "client_request_id": ""}
79	2026-02-25 10:52:39.982162+08	info	http.access	http request completed	0e3d9ec9-ac6e-4b82-9f7f-bc19c88dc8be	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/SettingsView-BPs_64pN.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "0e3d9ec9-ac6e-4b82-9f7f-bc19c88dc8be", "status_code": 200, "completed_at": "2026-02-25T10:52:39.982152635+08:00", "client_request_id": ""}
80	2026-02-25 10:52:40.00285+08	info	http.access	http request completed	9876c60b-4e49-406a-ae45-bb0a272cd42f	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/settings/stream-timeout", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "9876c60b-4e49-406a-ae45-bb0a272cd42f", "status_code": 200, "completed_at": "2026-02-25T10:52:40.002824201+08:00", "client_request_id": ""}
81	2026-02-25 10:52:40.002889+08	info	http.access	http request completed	b4c626d3-78dc-4584-91e6-dcc139fb3ecd	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/settings", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "b4c626d3-78dc-4584-91e6-dcc139fb3ecd", "status_code": 200, "completed_at": "2026-02-25T10:52:40.0028743+08:00", "client_request_id": ""}
82	2026-02-25 10:52:40.00338+08	info	http.access	http request completed	09e77b10-8e40-4083-a1f3-c37c7fb7efee	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/settings/admin-api-key", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "09e77b10-8e40-4083-a1f3-c37c7fb7efee", "status_code": 200, "completed_at": "2026-02-25T10:52:40.003370197+08:00", "client_request_id": ""}
83	2026-02-25 10:52:40.004785+08	info	http.access	http request completed	3b93b2e9-023a-4665-8736-df70e22e435a	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/announcements", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 4, "request_id": "3b93b2e9-023a-4665-8736-df70e22e435a", "status_code": 200, "completed_at": "2026-02-25T10:52:40.004758788+08:00", "client_request_id": ""}
84	2026-02-25 10:53:29.001791+08	info	http.access	http request completed	8cdcf6cd-a57d-40e3-a016-19d5023bb57f	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "8cdcf6cd-a57d-40e3-a016-19d5023bb57f", "status_code": 200, "completed_at": "2026-02-25T10:53:29.001775124+08:00", "client_request_id": ""}
85	2026-02-25 10:54:28.999442+08	info	http.access	http request completed	43741856-dcc2-4d39-9ae6-298a74c5f376	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "43741856-dcc2-4d39-9ae6-298a74c5f376", "status_code": 200, "completed_at": "2026-02-25T10:54:28.999424757+08:00", "client_request_id": ""}
86	2026-02-25 10:55:29.005648+08	info	http.access	http request completed	0832e185-7e13-45d8-a703-45f98011e52f	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "0832e185-7e13-45d8-a703-45f98011e52f", "status_code": 200, "completed_at": "2026-02-25T10:55:29.005632846+08:00", "client_request_id": ""}
87	2026-02-25 10:56:29.000404+08	info	http.access	http request completed	4f367ff4-87c2-4d1e-8135-c632460f0224	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "4f367ff4-87c2-4d1e-8135-c632460f0224", "status_code": 200, "completed_at": "2026-02-25T10:56:29.00038766+08:00", "client_request_id": ""}
88	2026-02-25 10:57:28.992515+08	info	http.access	http request completed	4a6b5e47-8ad7-4259-bcec-7fab14f67c0c	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "4a6b5e47-8ad7-4259-bcec-7fab14f67c0c", "status_code": 200, "completed_at": "2026-02-25T10:57:28.992501875+08:00", "client_request_id": ""}
89	2026-02-25 10:57:28.993044+08	info	http.access	http request completed	7a5f1cf6-9916-419b-8785-bf5ee92fc7be	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/subscriptions/active", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 1, "request_id": "7a5f1cf6-9916-419b-8785-bf5ee92fc7be", "status_code": 200, "completed_at": "2026-02-25T10:57:28.993035372+08:00", "client_request_id": ""}
90	2026-02-25 10:58:16.536254+08	info	http.access	http request completed	a58c2f26-b85d-4a95-ad78-9712d4b37a77	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/settings", "method": "PUT", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 47, "request_id": "a58c2f26-b85d-4a95-ad78-9712d4b37a77", "status_code": 200, "completed_at": "2026-02-25T10:58:16.536240362+08:00", "client_request_id": ""}
91	2026-02-25 10:58:16.541461+08	info	http.access	http request completed	79a7ebf8-f2e3-4739-866c-159f645a333c	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/settings/public", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "79a7ebf8-f2e3-4739-866c-159f645a333c", "status_code": 200, "completed_at": "2026-02-25T10:58:16.541448431+08:00", "client_request_id": ""}
92	2026-02-25 10:58:29.00181+08	info	http.access	http request completed	040d81af-e3d5-4046-a1c4-3e861776964b	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "040d81af-e3d5-4046-a1c4-3e861776964b", "status_code": 200, "completed_at": "2026-02-25T10:58:29.001791935+08:00", "client_request_id": ""}
93	2026-02-25 10:58:29.119821+08	info	http.access	http request completed	e2e5f5d7-cfe9-47d7-b0bb-fdbea391b5d1	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/ProfileView-CGH-7J6v.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "e2e5f5d7-cfe9-47d7-b0bb-fdbea391b5d1", "status_code": 200, "completed_at": "2026-02-25T10:58:29.119803739+08:00", "client_request_id": ""}
94	2026-02-25 10:58:29.175319+08	info	http.access	http request completed	3455cd73-c9e2-4206-adbf-f45ed8ec5740	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/announcements", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 4, "request_id": "3455cd73-c9e2-4206-adbf-f45ed8ec5740", "status_code": 200, "completed_at": "2026-02-25T10:58:29.175279612+08:00", "client_request_id": ""}
95	2026-02-25 10:58:29.179697+08	info	http.access	http request completed	e622f0de-d6d4-4be6-a2b0-f47e758e83ac	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/subscriptions/active", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "e622f0de-d6d4-4be6-a2b0-f47e758e83ac", "status_code": 200, "completed_at": "2026-02-25T10:58:29.179638586+08:00", "client_request_id": ""}
96	2026-02-25 10:58:29.181832+08	info	http.access	http request completed	01dc3630-0380-4d09-9872-05b07ac2924e	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/settings/public", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "01dc3630-0380-4d09-9872-05b07ac2924e", "status_code": 200, "completed_at": "2026-02-25T10:58:29.181804873+08:00", "client_request_id": ""}
97	2026-02-25 10:58:29.184995+08	info	http.access	http request completed	5d48861f-94a2-4d71-874f-e30959ad46e8	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/user/totp/status", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 4, "request_id": "5d48861f-94a2-4d71-874f-e30959ad46e8", "status_code": 200, "completed_at": "2026-02-25T10:58:29.184955454+08:00", "client_request_id": ""}
115	2026-02-25 11:00:10.712418+08	info	http.access	http request completed	548f017f-8928-4448-b64a-2df2ace5f6a9	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "548f017f-8928-4448-b64a-2df2ace5f6a9", "status_code": 200, "completed_at": "2026-02-25T11:00:10.712403186+08:00", "client_request_id": ""}
116	2026-02-25 11:00:18.896555+08	info	http.access	http request completed	d529425b-61be-43ee-b6ee-6f76888be9fe	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/logout", "method": "POST", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "d529425b-61be-43ee-b6ee-6f76888be9fe", "status_code": 200, "completed_at": "2026-02-25T11:00:18.896541574+08:00", "client_request_id": ""}
117	2026-02-25 11:00:18.935614+08	info	http.access	http request completed	84e9ca1e-f3af-4141-b948-275223b5b6c7	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/settings/public", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 1, "request_id": "84e9ca1e-f3af-4141-b948-275223b5b6c7", "status_code": 200, "completed_at": "2026-02-25T11:00:18.935592048+08:00", "client_request_id": ""}
98	2026-02-25 10:58:59.629142+08	info	http.access	http request completed	ea69a1ff-98cc-4135-a6c2-14228e3c5075	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/user/password", "method": "PUT", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 114, "request_id": "ea69a1ff-98cc-4135-a6c2-14228e3c5075", "status_code": 200, "completed_at": "2026-02-25T10:58:59.629119271+08:00", "client_request_id": ""}
99	2026-02-25 10:59:06.354834+08	info	http.access	http request completed	00821aaa-a46e-40fe-adb7-8d668f55fe31	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/logout", "method": "POST", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "00821aaa-a46e-40fe-adb7-8d668f55fe31", "status_code": 200, "completed_at": "2026-02-25T10:59:06.354818109+08:00", "client_request_id": ""}
100	2026-02-25 10:59:06.379639+08	info	http.access	http request completed	ef8649c4-e879-4898-bdc2-6356e61b869e	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/settings/public", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 1, "request_id": "ef8649c4-e879-4898-bdc2-6356e61b869e", "status_code": 200, "completed_at": "2026-02-25T10:59:06.379577163+08:00", "client_request_id": ""}
101	2026-02-25 10:59:10.691752+08	info	http.access	http request completed	02e40419-9734-405e-a71f-a5186e44c57f	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/login", "method": "POST", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 52, "request_id": "02e40419-9734-405e-a71f-a5186e44c57f", "status_code": 200, "completed_at": "2026-02-25T10:59:10.691733062+08:00", "client_request_id": ""}
102	2026-02-25 10:59:10.699043+08	info	http.access	http request completed	d75fd491-495b-416c-8bb8-9efd538df742	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/subscriptions/active", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "d75fd491-495b-416c-8bb8-9efd538df742", "status_code": 200, "completed_at": "2026-02-25T10:59:10.699015819+08:00", "client_request_id": ""}
103	2026-02-25 10:59:10.715106+08	info	http.access	http request completed	fb465b3b-8b91-4803-8308-2af507cf8a0a	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 4, "request_id": "fb465b3b-8b91-4803-8308-2af507cf8a0a", "status_code": 200, "completed_at": "2026-02-25T10:59:10.715080124+08:00", "client_request_id": ""}
104	2026-02-25 10:59:10.715281+08	info	http.access	http request completed	943a3e2d-e46e-41f1-b9ed-63da9dc4e0e9	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage/dashboard/trend", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "943a3e2d-e46e-41f1-b9ed-63da9dc4e0e9", "status_code": 200, "completed_at": "2026-02-25T10:59:10.715265923+08:00", "client_request_id": ""}
105	2026-02-25 10:59:10.715283+08	info	http.access	http request completed	12475b0e-736a-4296-9a0a-25b892af4c56	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage/dashboard/models", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "12475b0e-736a-4296-9a0a-25b892af4c56", "status_code": 200, "completed_at": "2026-02-25T10:59:10.715271823+08:00", "client_request_id": ""}
106	2026-02-25 10:59:10.717551+08	info	http.access	http request completed	03f16c3d-63cd-4190-a95f-476a89801520	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/announcements", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 7, "request_id": "03f16c3d-63cd-4190-a95f-476a89801520", "status_code": 200, "completed_at": "2026-02-25T10:59:10.71752891+08:00", "client_request_id": ""}
107	2026-02-25 10:59:10.717659+08	info	http.access	http request completed	7adb1753-a235-4781-8d88-432e617440f8	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "7adb1753-a235-4781-8d88-432e617440f8", "status_code": 200, "completed_at": "2026-02-25T10:59:10.717638809+08:00", "client_request_id": ""}
108	2026-02-25 10:59:10.729408+08	info	http.access	http request completed	2e3ab24d-676b-4df4-948a-e6fcd0596889	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage/dashboard/stats", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 5, "request_id": "2e3ab24d-676b-4df4-948a-e6fcd0596889", "status_code": 200, "completed_at": "2026-02-25T10:59:10.72937794+08:00", "client_request_id": ""}
109	2026-02-25 10:59:13.703759+08	info	http.access	http request completed	771dc539-3525-47ad-bb41-0331a87fcf5b	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/settings/admin-api-key", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "771dc539-3525-47ad-bb41-0331a87fcf5b", "status_code": 200, "completed_at": "2026-02-25T10:59:13.703733719+08:00", "client_request_id": ""}
110	2026-02-25 10:59:13.704309+08	info	http.access	http request completed	1becbea7-8f88-43c8-8a31-6fb116f85b81	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/settings/stream-timeout", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "1becbea7-8f88-43c8-8a31-6fb116f85b81", "status_code": 200, "completed_at": "2026-02-25T10:59:13.704294915+08:00", "client_request_id": ""}
111	2026-02-25 10:59:13.704434+08	info	http.access	http request completed	ea9a3b31-5386-42a1-925f-f848ed90a7a9	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/settings", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "ea9a3b31-5386-42a1-925f-f848ed90a7a9", "status_code": 200, "completed_at": "2026-02-25T10:59:13.704414315+08:00", "client_request_id": ""}
112	2026-02-25 10:59:13.70676+08	info	http.access	http request completed	4600f09c-7466-4102-99bf-701c3eded366	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/announcements", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 5, "request_id": "4600f09c-7466-4102-99bf-701c3eded366", "status_code": 200, "completed_at": "2026-02-25T10:59:13.706735001+08:00", "client_request_id": ""}
113	2026-02-25 11:00:05.942001+08	info	http.access	http request completed	cd2a6cb8-b707-4d36-9b75-fc0d78757e43	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/settings", "method": "PUT", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 51, "request_id": "cd2a6cb8-b707-4d36-9b75-fc0d78757e43", "status_code": 200, "completed_at": "2026-02-25T11:00:05.941961085+08:00", "client_request_id": ""}
114	2026-02-25 11:00:05.946574+08	info	http.access	http request completed	b0b94f65-4b84-4dd2-9fe4-1cee15ea3fed	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/settings/public", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "b0b94f65-4b84-4dd2-9fe4-1cee15ea3fed", "status_code": 200, "completed_at": "2026-02-25T11:00:05.946548458+08:00", "client_request_id": ""}
118	2026-02-25 11:00:47.491824+08	info	http.access	http request completed	33c929c5-3e92-4270-9f0f-df3b0e8f31ad	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/login", "method": "POST", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 13, "request_id": "33c929c5-3e92-4270-9f0f-df3b0e8f31ad", "status_code": 401, "completed_at": "2026-02-25T11:00:47.491780016+08:00", "client_request_id": ""}
119	2026-02-25 11:01:19.655881+08	error	service.pricing	[Pricing] Failed to compute local hash: open data/model_pricing.json: no such file or directory	\N	\N	\N	\N	\N	\N	{"env": "production", "service": "sub2api", "component": "service.pricing", "legacy_printf": true}
120	2026-02-25 11:01:29.656992+08	error	service.pricing	[Pricing] Sync failed: fetch remote hash: Get "https://raw.githubusercontent.com/Wei-Shaw/claude-relay-service/price-mirror/model_prices_and_context_window.sha256": context deadline exceeded	\N	\N	\N	\N	\N	\N	{"env": "production", "service": "sub2api", "component": "service.pricing", "legacy_printf": true}
121	2026-02-25 11:02:47.904784+08	warn	stdlog	Warning: server.trusted_proxies is empty in release mode; client IP trust chain is disabled	\N	\N	\N	\N	\N	\N	{"env": "production", "service": "sub2api", "legacy_stdlog": true}
122	2026-02-25 11:02:47.904824+08	warn	stdlog	Warning: CORS allowed_origins not configured; cross-origin requests will be rejected.	\N	\N	\N	\N	\N	\N	{"env": "production", "service": "sub2api", "legacy_stdlog": true}
123	2026-02-25 11:02:48.022666+08	error	stdlog	[LDAP] user search failed identifier=wanghongping: error: code=*** reason="USER_NOT_FOUND" message="user not found" metadata=map[]	\N	\N	\N	\N	\N	\N	{"env": "production", "service": "sub2api", "legacy_stdlog": true}
124	2026-02-25 11:02:48.022974+08	info	http.access	http request completed	7ad361dc-1d6a-45f9-aba4-a016c3df52f7	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/login", "method": "POST", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 11, "request_id": "7ad361dc-1d6a-45f9-aba4-a016c3df52f7", "status_code": 401, "completed_at": "2026-02-25T11:02:48.022953182+08:00", "client_request_id": ""}
125	2026-02-25 11:02:49.272587+08	info	http.access	http request completed	4569dfc5-458e-42fa-96c8-20c238ee5314	\N	\N	\N	\N	\N	{"env": "production", "path": "/login", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 1, "request_id": "4569dfc5-458e-42fa-96c8-20c238ee5314", "status_code": 200, "completed_at": "2026-02-25T11:02:49.272537063+08:00", "client_request_id": ""}
126	2026-02-25 11:02:49.298774+08	info	http.access	http request completed	a5e46b98-500e-4bf5-8ad2-27ab30d623de	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/index-CrU_eI8r.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "a5e46b98-500e-4bf5-8ad2-27ab30d623de", "status_code": 200, "completed_at": "2026-02-25T11:02:49.298752311+08:00", "client_request_id": ""}
127	2026-02-25 11:02:49.299228+08	info	http.access	http request completed	0b3d093c-0769-43e8-a5e7-746feb0accf3	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/vendor-vue-4WNFgugS.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "0b3d093c-0769-43e8-a5e7-746feb0accf3", "status_code": 200, "completed_at": "2026-02-25T11:02:49.299189508+08:00", "client_request_id": ""}
128	2026-02-25 11:02:49.302189+08	info	http.access	http request completed	ec17e053-36d6-46a9-aadf-2ee217bb5120	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/vendor-misc-NmuJm1mp.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "ec17e053-36d6-46a9-aadf-2ee217bb5120", "status_code": 200, "completed_at": "2026-02-25T11:02:49.302170891+08:00", "client_request_id": ""}
129	2026-02-25 11:02:49.302377+08	info	http.access	http request completed	82aa1ad5-689a-425b-9df6-ad563aca7571	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/vendor-i18n-CF5oKjnm.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "82aa1ad5-689a-425b-9df6-ad563aca7571", "status_code": 200, "completed_at": "2026-02-25T11:02:49.30236279+08:00", "client_request_id": ""}
130	2026-02-25 11:02:49.318788+08	info	http.access	http request completed	1d803c22-6631-42df-b725-63163fc9b46a	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/vendor-misc-DB0Q8XAf.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "1d803c22-6631-42df-b725-63163fc9b46a", "status_code": 200, "completed_at": "2026-02-25T11:02:49.318775094+08:00", "client_request_id": ""}
131	2026-02-25 11:02:49.319397+08	info	http.access	http request completed	b76789ea-81e7-45bc-a789-56bda598a26d	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/index-Dji9Snxu.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "b76789ea-81e7-45bc-a789-56bda598a26d", "status_code": 200, "completed_at": "2026-02-25T11:02:49.319364591+08:00", "client_request_id": ""}
132	2026-02-25 11:02:49.449578+08	info	http.access	http request completed	94c74c89-2aa1-40b4-9abc-8de298ee14e5	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/zh-joyDK6VH.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "94c74c89-2aa1-40b4-9abc-8de298ee14e5", "status_code": 200, "completed_at": "2026-02-25T11:02:49.449562233+08:00", "client_request_id": ""}
133	2026-02-25 11:02:49.449986+08	info	http.access	http request completed	3c909b8d-7e73-42ff-87aa-61009bdb2632	\N	\N	\N	\N	\N	{"env": "production", "path": "/logo.png", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "3c909b8d-7e73-42ff-87aa-61009bdb2632", "status_code": 200, "completed_at": "2026-02-25T11:02:49.449972231+08:00", "client_request_id": ""}
134	2026-02-25 11:02:49.471034+08	info	http.access	http request completed	c12f63ec-063e-428e-96df-166350aa5eb1	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/AuthLayout-BLY8cBK0.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "c12f63ec-063e-428e-96df-166350aa5eb1", "status_code": 200, "completed_at": "2026-02-25T11:02:49.471021708+08:00", "client_request_id": ""}
135	2026-02-25 11:02:49.471034+08	info	http.access	http request completed	42637036-35ab-4656-aeca-30e3c9f8f488	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/AuthLayout-D_5JJD4j.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "42637036-35ab-4656-aeca-30e3c9f8f488", "status_code": 200, "completed_at": "2026-02-25T11:02:49.471021808+08:00", "client_request_id": ""}
136	2026-02-25 11:02:49.471135+08	info	http.access	http request completed	e7ea28a5-0e40-4d30-9650-bed31c851e10	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/TurnstileWidget-CtZXX_iR.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "e7ea28a5-0e40-4d30-9650-bed31c851e10", "status_code": 200, "completed_at": "2026-02-25T11:02:49.471123708+08:00", "client_request_id": ""}
137	2026-02-25 11:02:49.471141+08	info	http.access	http request completed	c08373f5-a100-47cb-aed2-8d4cc2bf9df8	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/LinuxDoOAuthSection.vue_vue_type_script_setup_true_lang-DJujUfeo.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "c08373f5-a100-47cb-aed2-8d4cc2bf9df8", "status_code": 200, "completed_at": "2026-02-25T11:02:49.471131508+08:00", "client_request_id": ""}
138	2026-02-25 11:02:49.471275+08	info	http.access	http request completed	a8123d14-f1ff-4124-b0fc-3d60d357f6d4	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/LoginView-Dm2m7DcW.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "a8123d14-f1ff-4124-b0fc-3d60d357f6d4", "status_code": 200, "completed_at": "2026-02-25T11:02:49.471263407+08:00", "client_request_id": ""}
139	2026-02-25 11:02:49.471554+08	info	http.access	http request completed	6f5400da-8ecb-4fc6-a010-c25dd6aca4f4	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/TurnstileWidget-9t9fJkOj.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "6f5400da-8ecb-4fc6-a010-c25dd6aca4f4", "status_code": 200, "completed_at": "2026-02-25T11:02:49.471542605+08:00", "client_request_id": ""}
140	2026-02-25 11:02:49.474911+08	info	http.access	http request completed	84d3917b-cfcd-44a0-991e-ab6ebc01d848	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/LoginView-CM0iaiMq.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "84d3917b-cfcd-44a0-991e-ab6ebc01d848", "status_code": 200, "completed_at": "2026-02-25T11:02:49.474898686+08:00", "client_request_id": ""}
141	2026-02-25 11:02:49.475001+08	info	http.access	http request completed	dd00aa83-1e22-4ae4-8afc-416ecc6683fc	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/LocaleSwitcher-CjvPxOhx.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "dd00aa83-1e22-4ae4-8afc-416ecc6683fc", "status_code": 200, "completed_at": "2026-02-25T11:02:49.474994285+08:00", "client_request_id": ""}
142	2026-02-25 11:02:49.475122+08	info	http.access	http request completed	c511d6d2-379e-413b-a22b-e4e2a6e4cc1d	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/AppHeader-NeOcFzPI.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "c511d6d2-379e-413b-a22b-e4e2a6e4cc1d", "status_code": 200, "completed_at": "2026-02-25T11:02:49.475103385+08:00", "client_request_id": ""}
143	2026-02-25 11:02:49.489237+08	info	http.access	http request completed	b6848ed0-49a4-4822-a2d1-50720559ac8d	\N	\N	\N	\N	\N	{"env": "production", "path": "/logo.png", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "b6848ed0-49a4-4822-a2d1-50720559ac8d", "status_code": 200, "completed_at": "2026-02-25T11:02:49.489193703+08:00", "client_request_id": ""}
144	2026-02-25 11:02:49.500141+08	info	http.access	http request completed	3472a1f7-c8a4-4afe-8b5f-153e16264795	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/settings/public", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 1, "request_id": "3472a1f7-c8a4-4afe-8b5f-153e16264795", "status_code": 200, "completed_at": "2026-02-25T11:02:49.500119639+08:00", "client_request_id": ""}
145	2026-02-25 11:02:51.250239+08	info	http.access	http request completed	c858b78d-dfbf-4932-a863-45a34cb0e330	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/login", "method": "POST", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 52, "request_id": "c858b78d-dfbf-4932-a863-45a34cb0e330", "status_code": 200, "completed_at": "2026-02-25T11:02:51.250224757+08:00", "client_request_id": ""}
146	2026-02-25 11:02:51.257602+08	info	http.access	http request completed	cfd96019-182d-4bdd-bc77-57d85ca7b7aa	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/usage-BlWL46gW.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "cfd96019-182d-4bdd-bc77-57d85ca7b7aa", "status_code": 200, "completed_at": "2026-02-25T11:02:51.257571214+08:00", "client_request_id": ""}
147	2026-02-25 11:02:51.257693+08	info	http.access	http request completed	81807abe-2fab-40bf-857a-697b886cd6f7	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/DashboardView-DVWIfxM4.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "81807abe-2fab-40bf-857a-697b886cd6f7", "status_code": 200, "completed_at": "2026-02-25T11:02:51.257673514+08:00", "client_request_id": ""}
148	2026-02-25 11:02:51.257836+08	info	http.access	http request completed	e4d72644-af5e-4b6c-b4a8-a7314b12013e	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/LocaleSwitcher-CJSwBRWY.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "e4d72644-af5e-4b6c-b4a8-a7314b12013e", "status_code": 200, "completed_at": "2026-02-25T11:02:51.257824713+08:00", "client_request_id": ""}
149	2026-02-25 11:02:51.258022+08	info	http.access	http request completed	4a957daa-f8ce-4930-8301-bc5a988eb10c	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/LoadingSpinner-CyStGumC.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "4a957daa-f8ce-4930-8301-bc5a988eb10c", "status_code": 200, "completed_at": "2026-02-25T11:02:51.258012712+08:00", "client_request_id": ""}
150	2026-02-25 11:02:51.25857+08	info	http.access	http request completed	69377df2-732b-439f-96b5-3732731450b4	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/AppLayout.vue_vue_type_script_setup_true_lang-CKTAlA0-.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "69377df2-732b-439f-96b5-3732731450b4", "status_code": 200, "completed_at": "2026-02-25T11:02:51.258552108+08:00", "client_request_id": ""}
151	2026-02-25 11:02:51.259281+08	info	http.access	http request completed	7761e205-8699-4399-b444-aa616d872d11	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/subscriptions/active", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 5, "request_id": "7761e205-8699-4399-b444-aa616d872d11", "status_code": 200, "completed_at": "2026-02-25T11:02:51.259269704+08:00", "client_request_id": ""}
152	2026-02-25 11:02:51.266686+08	info	http.access	http request completed	b23325f0-c9a7-4da0-8137-f8013d801ea9	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/LoadingSpinner-DT-rtrW_.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "b23325f0-c9a7-4da0-8137-f8013d801ea9", "status_code": 200, "completed_at": "2026-02-25T11:02:51.266676661+08:00", "client_request_id": ""}
153	2026-02-25 11:02:51.26684+08	info	http.access	http request completed	70a75174-5713-4e42-968a-ac55bef06ad5	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/DateRangePicker-CFGGkPM1.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "70a75174-5713-4e42-968a-ac55bef06ad5", "status_code": 200, "completed_at": "2026-02-25T11:02:51.26682816+08:00", "client_request_id": ""}
154	2026-02-25 11:02:51.266899+08	info	http.access	http request completed	c27ca8eb-49fa-48ea-a6d1-26c4cf006059	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/Select-7fPaeC0I.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "c27ca8eb-49fa-48ea-a6d1-26c4cf006059", "status_code": 200, "completed_at": "2026-02-25T11:02:51.26688916+08:00", "client_request_id": ""}
155	2026-02-25 11:02:51.267198+08	info	http.access	http request completed	39b2e069-e23e-4844-a747-94c1f6390506	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/DateRangePicker-4QcPOZ3x.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "39b2e069-e23e-4844-a747-94c1f6390506", "status_code": 200, "completed_at": "2026-02-25T11:02:51.267190758+08:00", "client_request_id": ""}
156	2026-02-25 11:02:51.270316+08	info	http.access	http request completed	ba251d2b-95c2-46d2-8c46-bf1bf3ca0f48	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/Select-M2m3gzLX.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "ba251d2b-95c2-46d2-8c46-bf1bf3ca0f48", "status_code": 200, "completed_at": "2026-02-25T11:02:51.27029974+08:00", "client_request_id": ""}
157	2026-02-25 11:02:51.270909+08	info	http.access	http request completed	80b20442-1678-4d48-802e-0db22dabf744	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/vendor-chart-BqAhThnj.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "80b20442-1678-4d48-802e-0db22dabf744", "status_code": 200, "completed_at": "2026-02-25T11:02:51.270891437+08:00", "client_request_id": ""}
158	2026-02-25 11:02:51.272112+08	info	http.access	http request completed	98b504ed-99cc-4a6f-a601-55547eadfc20	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/EmptyState.vue_vue_type_script_setup_true_lang-BuIi38rv.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "98b504ed-99cc-4a6f-a601-55547eadfc20", "status_code": 200, "completed_at": "2026-02-25T11:02:51.27210573+08:00", "client_request_id": ""}
159	2026-02-25 11:02:51.272101+08	info	http.access	http request completed	00fcf21e-6152-46c0-8acd-be86bd629283	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/TokenUsageTrend.vue_vue_type_script_setup_true_lang-DnDbESHW.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "00fcf21e-6152-46c0-8acd-be86bd629283", "status_code": 200, "completed_at": "2026-02-25T11:02:51.27209003+08:00", "client_request_id": ""}
160	2026-02-25 11:02:51.316454+08	info	http.access	http request completed	5964b1b5-7d32-4350-8775-db463f4bfb4b	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/settings", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "5964b1b5-7d32-4350-8775-db463f4bfb4b", "status_code": 200, "completed_at": "2026-02-25T11:02:51.316428172+08:00", "client_request_id": ""}
161	2026-02-25 11:02:51.318068+08	info	http.access	http request completed	cf523f6d-48d3-4ed6-8d99-abda1095942a	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/system/check-updates", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 4, "request_id": "cf523f6d-48d3-4ed6-8d99-abda1095942a", "status_code": 200, "completed_at": "2026-02-25T11:02:51.318035962+08:00", "client_request_id": ""}
162	2026-02-25 11:02:51.320867+08	info	http.access	http request completed	978658e6-bde7-4db2-9edc-c4e8cd7d16d9	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 6, "request_id": "978658e6-bde7-4db2-9edc-c4e8cd7d16d9", "status_code": 200, "completed_at": "2026-02-25T11:02:51.320837546+08:00", "client_request_id": ""}
163	2026-02-25 11:02:51.325752+08	info	http.access	http request completed	498eae1e-2b20-4172-ad44-40705b589771	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage/dashboard/models", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 11, "request_id": "498eae1e-2b20-4172-ad44-40705b589771", "status_code": 200, "completed_at": "2026-02-25T11:02:51.325741918+08:00", "client_request_id": ""}
164	2026-02-25 11:02:51.32575+08	info	http.access	http request completed	a4b7d375-5399-4606-9f3b-3efd9ae9558e	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 7, "request_id": "a4b7d375-5399-4606-9f3b-3efd9ae9558e", "status_code": 200, "completed_at": "2026-02-25T11:02:51.325723718+08:00", "client_request_id": ""}
165	2026-02-25 11:02:51.325767+08	info	http.access	http request completed	67ac903a-74c1-44ac-ac94-c58c007fafdb	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage/dashboard/trend", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 11, "request_id": "67ac903a-74c1-44ac-ac94-c58c007fafdb", "status_code": 200, "completed_at": "2026-02-25T11:02:51.325745818+08:00", "client_request_id": ""}
166	2026-02-25 11:02:51.326303+08	info	http.access	http request completed	9c2611be-c294-4c4c-8925-318b6ae82abf	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/announcements", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 12, "request_id": "9c2611be-c294-4c4c-8925-318b6ae82abf", "status_code": 200, "completed_at": "2026-02-25T11:02:51.326288414+08:00", "client_request_id": ""}
167	2026-02-25 11:02:51.331582+08	info	http.access	http request completed	0cc923c8-6393-48c1-9c81-84ec1a1572de	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/KeysView-CCSOZ5fG.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "0cc923c8-6393-48c1-9c81-84ec1a1572de", "status_code": 200, "completed_at": "2026-02-25T11:02:51.331559584+08:00", "client_request_id": ""}
168	2026-02-25 11:02:51.331938+08	info	http.access	http request completed	43568f65-d580-4655-8d9c-7329324cb3be	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/useClipboard-CYH4PDKz.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "43568f65-d580-4655-8d9c-7329324cb3be", "status_code": 200, "completed_at": "2026-02-25T11:02:51.331925882+08:00", "client_request_id": ""}
169	2026-02-25 11:02:51.332144+08	info	http.access	http request completed	6cc802be-be6b-428b-bc78-cd323fb3043d	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/keys-_v9ZnNui.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "6cc802be-be6b-428b-bc78-cd323fb3043d", "status_code": 200, "completed_at": "2026-02-25T11:02:51.33212518+08:00", "client_request_id": ""}
170	2026-02-25 11:02:51.332312+08	info	http.access	http request completed	5209fccc-4a2a-48cc-ad01-81653ee9d73b	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/TablePageLayout-eKTo0RsV.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "5209fccc-4a2a-48cc-ad01-81653ee9d73b", "status_code": 200, "completed_at": "2026-02-25T11:02:51.332299679+08:00", "client_request_id": ""}
171	2026-02-25 11:02:51.332386+08	info	http.access	http request completed	99a5b8a1-3537-44ea-a35a-8f6c781515ee	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/TablePageLayout-BIThKX5Z.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "99a5b8a1-3537-44ea-a35a-8f6c781515ee", "status_code": 200, "completed_at": "2026-02-25T11:02:51.332368879+08:00", "client_request_id": ""}
172	2026-02-25 11:02:51.34019+08	info	http.access	http request completed	68cbd97e-9c3c-4c6f-97a4-b7c73a48383f	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/DataTable-wk4w1kiu.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "68cbd97e-9c3c-4c6f-97a4-b7c73a48383f", "status_code": 200, "completed_at": "2026-02-25T11:02:51.340173234+08:00", "client_request_id": ""}
173	2026-02-25 11:02:51.340277+08	info	http.access	http request completed	88053442-e5c0-43a1-92ef-f48027cd4bf6	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage/dashboard/stats", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 10, "request_id": "88053442-e5c0-43a1-92ef-f48027cd4bf6", "status_code": 200, "completed_at": "2026-02-25T11:02:51.340258533+08:00", "client_request_id": ""}
174	2026-02-25 11:02:51.342761+08	info	http.access	http request completed	0547e495-6dc3-43a8-abb7-e8a698e3ef1b	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/Pagination-DtcDDVEA.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "0547e495-6dc3-43a8-abb7-e8a698e3ef1b", "status_code": 200, "completed_at": "2026-02-25T11:02:51.342744319+08:00", "client_request_id": ""}
175	2026-02-25 11:02:51.343019+08	info	http.access	http request completed	bcdb05e2-26f7-4200-afcd-27811f07ee1d	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/Pagination-Cy120BZx.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "bcdb05e2-26f7-4200-afcd-27811f07ee1d", "status_code": 200, "completed_at": "2026-02-25T11:02:51.342998217+08:00", "client_request_id": ""}
176	2026-02-25 11:02:51.343066+08	info	http.access	http request completed	1191d889-c33c-435d-ae64-4348f6cd4b34	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/DataTable-BSDXutJh.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "1191d889-c33c-435d-ae64-4348f6cd4b34", "status_code": 200, "completed_at": "2026-02-25T11:02:51.343053017+08:00", "client_request_id": ""}
177	2026-02-25 11:02:51.343306+08	info	http.access	http request completed	0ae72b13-20dd-4e8e-a2a5-6165c0f2b919	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/ConfirmDialog.vue_vue_type_script_setup_true_lang-Brt6MSpz.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "0ae72b13-20dd-4e8e-a2a5-6165c0f2b919", "status_code": 200, "completed_at": "2026-02-25T11:02:51.343294115+08:00", "client_request_id": ""}
178	2026-02-25 11:02:51.34952+08	info	http.access	http request completed	f517c7a4-8e40-47fc-a66b-b0eb93234aac	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/GroupBadge.vue_vue_type_script_setup_true_lang-Cej1HtUK.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "f517c7a4-8e40-47fc-a66b-b0eb93234aac", "status_code": 200, "completed_at": "2026-02-25T11:02:51.349499379+08:00", "client_request_id": ""}
179	2026-02-25 11:02:51.349582+08	info	http.access	http request completed	e9a7eaf9-a14b-438c-9559-6fd57ec4518a	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/PlatformIcon.vue_vue_type_script_setup_true_lang-DDJ5Ol8Z.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "e9a7eaf9-a14b-438c-9559-6fd57ec4518a", "status_code": 200, "completed_at": "2026-02-25T11:02:51.349566679+08:00", "client_request_id": ""}
180	2026-02-25 11:02:51.350768+08	info	http.access	http request completed	069c34af-3a05-4d02-bca5-9a3589344bae	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/GroupOptionItem.vue_vue_type_script_setup_true_lang-DJgQlkUJ.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "069c34af-3a05-4d02-bca5-9a3589344bae", "status_code": 200, "completed_at": "2026-02-25T11:02:51.350740372+08:00", "client_request_id": ""}
181	2026-02-25 11:02:51.351167+08	info	http.access	http request completed	282e9f55-68b3-498c-99dc-9a518e7e4b2e	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/UsageView-WokokQ3Q.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "282e9f55-68b3-498c-99dc-9a518e7e4b2e", "status_code": 200, "completed_at": "2026-02-25T11:02:51.35114157+08:00", "client_request_id": ""}
182	2026-02-25 11:02:53.808473+08	info	http.access	http request completed	60234247-ecaf-4ef8-bff0-4166dbef0bc0	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/Toggle.vue_vue_type_script_setup_true_lang-B0FKZlYT.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "60234247-ecaf-4ef8-bff0-4166dbef0bc0", "status_code": 200, "completed_at": "2026-02-25T11:02:53.808455373+08:00", "client_request_id": ""}
183	2026-02-25 11:02:53.808604+08	info	http.access	http request completed	cb3498bf-1613-492a-964b-53e3b9ba9df3	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/SettingsView-BPs_64pN.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "cb3498bf-1613-492a-964b-53e3b9ba9df3", "status_code": 200, "completed_at": "2026-02-25T11:02:53.808594572+08:00", "client_request_id": ""}
184	2026-02-25 11:02:53.839922+08	info	http.access	http request completed	0d373d7b-fada-4e3c-bcca-bb78c15c7bd3	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/settings/stream-timeout", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "0d373d7b-fada-4e3c-bcca-bb78c15c7bd3", "status_code": 200, "completed_at": "2026-02-25T11:02:53.83988249+08:00", "client_request_id": ""}
185	2026-02-25 11:02:53.839963+08	info	http.access	http request completed	b0e6d3a7-c307-4a21-b24d-e4544b2b4c1f	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/settings", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "b0e6d3a7-c307-4a21-b24d-e4544b2b4c1f", "status_code": 200, "completed_at": "2026-02-25T11:02:53.83993619+08:00", "client_request_id": ""}
186	2026-02-25 11:02:53.840482+08	info	http.access	http request completed	8a8d365a-12ac-4c9c-96e7-56c72eae49c7	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/settings/admin-api-key", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "8a8d365a-12ac-4c9c-96e7-56c72eae49c7", "status_code": 200, "completed_at": "2026-02-25T11:02:53.840463087+08:00", "client_request_id": ""}
187	2026-02-25 11:02:53.846427+08	info	http.access	http request completed	6d9535ad-0ba7-4ffd-b600-6110faa29c09	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/announcements", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 9, "request_id": "6d9535ad-0ba7-4ffd-b600-6110faa29c09", "status_code": 200, "completed_at": "2026-02-25T11:02:53.846390152+08:00", "client_request_id": ""}
188	2026-02-25 11:02:59.880607+08	info	http.access	http request completed	1d4ff77d-a68c-4d38-a21f-3b91a256536b	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/logout", "method": "POST", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "1d4ff77d-a68c-4d38-a21f-3b91a256536b", "status_code": 200, "completed_at": "2026-02-25T11:02:59.880593493+08:00", "client_request_id": ""}
189	2026-02-25 11:02:59.907384+08	info	http.access	http request completed	f1c7379a-d749-4b68-9437-898b87b27b87	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/settings/public", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 1, "request_id": "f1c7379a-d749-4b68-9437-898b87b27b87", "status_code": 200, "completed_at": "2026-02-25T11:02:59.907358238+08:00", "client_request_id": ""}
190	2026-02-25 11:03:10.851558+08	error	stdlog	[LDAP] user search failed identifier=wanghongping: error: code=*** reason="USER_NOT_FOUND" message="user not found" metadata=map[]	\N	\N	\N	\N	\N	\N	{"env": "production", "service": "sub2api", "legacy_stdlog": true}
191	2026-02-25 11:03:10.851722+08	info	http.access	http request completed	7b89cc67-c15e-41ff-aa82-9dedea61de79	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/login", "method": "POST", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 9, "request_id": "7b89cc67-c15e-41ff-aa82-9dedea61de79", "status_code": 401, "completed_at": "2026-02-25T11:03:10.851708483+08:00", "client_request_id": ""}
192	2026-02-25 11:03:29.252899+08	info	http.access	http request completed	ac3860d5-92a8-4a94-958f-302ce8c374bd	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/login", "method": "POST", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 53, "request_id": "ac3860d5-92a8-4a94-958f-302ce8c374bd", "status_code": 200, "completed_at": "2026-02-25T11:03:29.252883002+08:00", "client_request_id": ""}
193	2026-02-25 11:03:29.263418+08	info	http.access	http request completed	9c6d51b8-a744-41ab-8549-66de6fac38da	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/subscriptions/active", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 5, "request_id": "9c6d51b8-a744-41ab-8549-66de6fac38da", "status_code": 200, "completed_at": "2026-02-25T11:03:29.263196542+08:00", "client_request_id": ""}
194	2026-02-25 11:03:29.274615+08	info	http.access	http request completed	14637329-8bd5-4445-8d76-35c8dd77c288	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage/dashboard/trend", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "14637329-8bd5-4445-8d76-35c8dd77c288", "status_code": 200, "completed_at": "2026-02-25T11:03:29.274568976+08:00", "client_request_id": ""}
195	2026-02-25 11:03:29.275245+08	info	http.access	http request completed	6a79399b-d9d3-4876-846b-f347857bd00a	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "6a79399b-d9d3-4876-846b-f347857bd00a", "status_code": 200, "completed_at": "2026-02-25T11:03:29.275208273+08:00", "client_request_id": ""}
196	2026-02-25 11:03:29.275288+08	info	http.access	http request completed	84856278-ebdf-4e47-b892-68f3f662c173	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage/dashboard/models", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "84856278-ebdf-4e47-b892-68f3f662c173", "status_code": 200, "completed_at": "2026-02-25T11:03:29.275257772+08:00", "client_request_id": ""}
197	2026-02-25 11:03:29.275299+08	info	http.access	http request completed	962ef8ca-9619-4ad3-bd98-76cce3296833	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "962ef8ca-9619-4ad3-bd98-76cce3296833", "status_code": 200, "completed_at": "2026-02-25T11:03:29.275283872+08:00", "client_request_id": ""}
198	2026-02-25 11:03:29.280344+08	info	http.access	http request completed	3779f904-4460-4181-bd1c-6cd669f8de1a	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/announcements", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 9, "request_id": "3779f904-4460-4181-bd1c-6cd669f8de1a", "status_code": 200, "completed_at": "2026-02-25T11:03:29.280317743+08:00", "client_request_id": ""}
199	2026-02-25 11:03:29.28731+08	info	http.access	http request completed	33f73f70-ccf9-4330-862b-625a95f810fc	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage/dashboard/stats", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 6, "request_id": "33f73f70-ccf9-4330-862b-625a95f810fc", "status_code": 200, "completed_at": "2026-02-25T11:03:29.287260903+08:00", "client_request_id": ""}
200	2026-02-25 11:03:31.924248+08	info	http.access	http request completed	a90ea285-375f-4de5-9f45-34aeb2c212c4	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/settings/admin-api-key", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "a90ea285-375f-4de5-9f45-34aeb2c212c4", "status_code": 200, "completed_at": "2026-02-25T11:03:31.924227685+08:00", "client_request_id": ""}
201	2026-02-25 11:03:31.924248+08	info	http.access	http request completed	16a4eba0-450e-4a30-9e52-113c55023617	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/settings/stream-timeout", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "16a4eba0-450e-4a30-9e52-113c55023617", "status_code": 200, "completed_at": "2026-02-25T11:03:31.924228885+08:00", "client_request_id": ""}
202	2026-02-25 11:03:31.924621+08	info	http.access	http request completed	3d30504b-091a-4c9b-b54a-d1f50c836ada	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/settings", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "3d30504b-091a-4c9b-b54a-d1f50c836ada", "status_code": 200, "completed_at": "2026-02-25T11:03:31.924605683+08:00", "client_request_id": ""}
203	2026-02-25 11:03:31.927051+08	info	http.access	http request completed	fcbf657d-c27f-4798-97a0-2e2d5f70649f	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/announcements", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 5, "request_id": "fcbf657d-c27f-4798-97a0-2e2d5f70649f", "status_code": 200, "completed_at": "2026-02-25T11:03:31.927011169+08:00", "client_request_id": ""}
204	2026-02-25 11:04:29.274238+08	info	http.access	http request completed	5241be1f-6f35-4ea3-b67e-99e6a88fad89	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 8, "request_id": "5241be1f-6f35-4ea3-b67e-99e6a88fad89", "status_code": 200, "completed_at": "2026-02-25T11:04:29.27416643+08:00", "client_request_id": ""}
205	2026-02-25 11:05:01.844019+08	warn	stdlog	Warning: server.trusted_proxies is empty in release mode; client IP trust chain is disabled	\N	\N	\N	\N	\N	\N	{"env": "production", "service": "sub2api", "legacy_stdlog": true}
206	2026-02-25 11:05:01.844066+08	warn	stdlog	Warning: CORS allowed_origins not configured; cross-origin requests will be rejected.	\N	\N	\N	\N	\N	\N	{"env": "production", "service": "sub2api", "legacy_stdlog": true}
207	2026-02-25 11:05:14.263542+08	info	http.access	http request completed	c1a0aad0-a1b7-462d-815f-2561383e6cea	\N	\N	\N	\N	\N	{"env": "production", "path": "/admin/settings", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 1, "request_id": "c1a0aad0-a1b7-462d-815f-2561383e6cea", "status_code": 200, "completed_at": "2026-02-25T11:05:14.263510742+08:00", "client_request_id": ""}
208	2026-02-25 11:05:14.289872+08	info	http.access	http request completed	781ccb9b-fba6-4f8d-a3e2-6aa6ecbbf357	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/index-CrU_eI8r.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "781ccb9b-fba6-4f8d-a3e2-6aa6ecbbf357", "status_code": 200, "completed_at": "2026-02-25T11:05:14.289836586+08:00", "client_request_id": ""}
209	2026-02-25 11:05:14.290189+08	info	http.access	http request completed	25a87609-a15d-4bdd-9f78-e5b52ea455a8	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/vendor-vue-4WNFgugS.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "25a87609-a15d-4bdd-9f78-e5b52ea455a8", "status_code": 200, "completed_at": "2026-02-25T11:05:14.290161584+08:00", "client_request_id": ""}
210	2026-02-25 11:05:14.29385+08	info	http.access	http request completed	af6757d5-40df-4146-a297-3164f3daa139	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/vendor-misc-DB0Q8XAf.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "af6757d5-40df-4146-a297-3164f3daa139", "status_code": 200, "completed_at": "2026-02-25T11:05:14.293832862+08:00", "client_request_id": ""}
211	2026-02-25 11:05:14.294681+08	info	http.access	http request completed	b8ad5dfc-2187-46e9-b45b-8a9e9ade6cd8	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/index-Dji9Snxu.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "b8ad5dfc-2187-46e9-b45b-8a9e9ade6cd8", "status_code": 200, "completed_at": "2026-02-25T11:05:14.294644457+08:00", "client_request_id": ""}
212	2026-02-25 11:05:14.295593+08	info	http.access	http request completed	588c8375-0220-4fe0-ac15-6ce4568d95e5	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/vendor-misc-NmuJm1mp.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "588c8375-0220-4fe0-ac15-6ce4568d95e5", "status_code": 200, "completed_at": "2026-02-25T11:05:14.295575252+08:00", "client_request_id": ""}
213	2026-02-25 11:05:14.29625+08	info	http.access	http request completed	5f5d41d3-ccd4-4676-a96e-c871e75e7679	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/vendor-i18n-CF5oKjnm.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "5f5d41d3-ccd4-4676-a96e-c871e75e7679", "status_code": 200, "completed_at": "2026-02-25T11:05:14.296241548+08:00", "client_request_id": ""}
214	2026-02-25 11:05:14.379175+08	info	http.access	http request completed	b373ccc8-d846-4ef1-8f1a-7bce303fe259	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/zh-joyDK6VH.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "b373ccc8-d846-4ef1-8f1a-7bce303fe259", "status_code": 200, "completed_at": "2026-02-25T11:05:14.379148057+08:00", "client_request_id": ""}
215	2026-02-25 11:05:14.379451+08	info	http.access	http request completed	9940af7f-fa1e-4678-a9ed-ebc45ba910cd	\N	\N	\N	\N	\N	{"env": "production", "path": "/logo.png", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "9940af7f-fa1e-4678-a9ed-ebc45ba910cd", "status_code": 200, "completed_at": "2026-02-25T11:05:14.379418755+08:00", "client_request_id": ""}
216	2026-02-25 11:05:14.402602+08	info	http.access	http request completed	207085bb-38c4-442a-8466-7e603172f3d7	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/SettingsView-BPs_64pN.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "207085bb-38c4-442a-8466-7e603172f3d7", "status_code": 200, "completed_at": "2026-02-25T11:05:14.402561118+08:00", "client_request_id": ""}
217	2026-02-25 11:05:14.403331+08	info	http.access	http request completed	6fc4b944-c2ea-46e1-ae29-002870ea9dcb	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/AppLayout.vue_vue_type_script_setup_true_lang-CKTAlA0-.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "6fc4b944-c2ea-46e1-ae29-002870ea9dcb", "status_code": 200, "completed_at": "2026-02-25T11:05:14.403281814+08:00", "client_request_id": ""}
218	2026-02-25 11:05:14.403516+08	info	http.access	http request completed	3a6cad56-3f50-4fc3-8d34-5f143816dcd4	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/LocaleSwitcher-CJSwBRWY.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "3a6cad56-3f50-4fc3-8d34-5f143816dcd4", "status_code": 200, "completed_at": "2026-02-25T11:05:14.403504012+08:00", "client_request_id": ""}
219	2026-02-25 11:05:14.407953+08	info	http.access	http request completed	2a73a98f-c5fb-4a9f-acef-85a49e701633	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/LocaleSwitcher-CjvPxOhx.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "2a73a98f-c5fb-4a9f-acef-85a49e701633", "status_code": 200, "completed_at": "2026-02-25T11:05:14.407934186+08:00", "client_request_id": ""}
220	2026-02-25 11:05:14.408117+08	info	http.access	http request completed	4e113b24-e0fd-45c0-8d49-de6f1ee76435	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 6, "request_id": "4e113b24-e0fd-45c0-8d49-de6f1ee76435", "status_code": 200, "completed_at": "2026-02-25T11:05:14.408096385+08:00", "client_request_id": ""}
221	2026-02-25 11:05:14.408162+08	info	http.access	http request completed	2df0ec8a-40d2-45a1-a864-2bf0957fc548	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/AppHeader-NeOcFzPI.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "2df0ec8a-40d2-45a1-a864-2bf0957fc548", "status_code": 200, "completed_at": "2026-02-25T11:05:14.408139885+08:00", "client_request_id": ""}
222	2026-02-25 11:05:14.413913+08	info	http.access	http request completed	7bc7232d-81f8-4c7c-b5ad-2c8cad958867	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/Toggle.vue_vue_type_script_setup_true_lang-B0FKZlYT.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "7bc7232d-81f8-4c7c-b5ad-2c8cad958867", "status_code": 200, "completed_at": "2026-02-25T11:05:14.413895051+08:00", "client_request_id": ""}
223	2026-02-25 11:05:14.416442+08	info	http.access	http request completed	5655c898-1e0b-491d-b187-abba86a7216e	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/useClipboard-CYH4PDKz.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "5655c898-1e0b-491d-b187-abba86a7216e", "status_code": 200, "completed_at": "2026-02-25T11:05:14.416410336+08:00", "client_request_id": ""}
224	2026-02-25 11:05:14.438709+08	info	http.access	http request completed	db8c4286-b73d-4f8a-8d61-4df762fd136a	\N	\N	\N	\N	\N	{"env": "production", "path": "/logo.png", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "db8c4286-b73d-4f8a-8d61-4df762fd136a", "status_code": 200, "completed_at": "2026-02-25T11:05:14.438677304+08:00", "client_request_id": ""}
225	2026-02-25 11:05:14.443946+08	info	http.access	http request completed	c5a70cb9-971c-4e18-910e-700d8cf1b572	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/subscriptions/active", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 4, "request_id": "c5a70cb9-971c-4e18-910e-700d8cf1b572", "status_code": 200, "completed_at": "2026-02-25T11:05:14.443918873+08:00", "client_request_id": ""}
226	2026-02-25 11:05:14.44732+08	info	http.access	http request completed	9d0ccaa2-1293-4150-a203-7a027e449378	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/settings", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "9d0ccaa2-1293-4150-a203-7a027e449378", "status_code": 200, "completed_at": "2026-02-25T11:05:14.447287853+08:00", "client_request_id": ""}
227	2026-02-25 11:05:14.448785+08	info	http.access	http request completed	112ab7c0-c1d7-4b1c-b958-b8a5624551e8	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/system/check-updates", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 4, "request_id": "112ab7c0-c1d7-4b1c-b958-b8a5624551e8", "status_code": 200, "completed_at": "2026-02-25T11:05:14.448743344+08:00", "client_request_id": ""}
228	2026-02-25 11:05:14.449866+08	info	http.access	http request completed	2f63baad-599c-4ad6-a2e1-a2363294c2c6	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/settings/admin-api-key", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 5, "request_id": "2f63baad-599c-4ad6-a2e1-a2363294c2c6", "status_code": 200, "completed_at": "2026-02-25T11:05:14.449834138+08:00", "client_request_id": ""}
229	2026-02-25 11:05:14.450972+08	info	http.access	http request completed	75de1a66-3fb3-4603-a8c1-c49ac7f030ea	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/settings/stream-timeout", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 5, "request_id": "75de1a66-3fb3-4603-a8c1-c49ac7f030ea", "status_code": 200, "completed_at": "2026-02-25T11:05:14.450956331+08:00", "client_request_id": ""}
230	2026-02-25 11:05:14.45245+08	info	http.access	http request completed	376a0477-72ec-48ea-a29e-d4ae3d51bcc4	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/settings", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "376a0477-72ec-48ea-a29e-d4ae3d51bcc4", "status_code": 200, "completed_at": "2026-02-25T11:05:14.452432123+08:00", "client_request_id": ""}
231	2026-02-25 11:05:14.454634+08	info	http.access	http request completed	6d69eba0-96b7-474e-943e-38fccd25d620	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/announcements", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 10, "request_id": "6d69eba0-96b7-474e-943e-38fccd25d620", "status_code": 200, "completed_at": "2026-02-25T11:05:14.45461221+08:00", "client_request_id": ""}
232	2026-02-25 11:05:16.067694+08	info	http.access	http request completed	46deed0a-591d-4f35-8e7e-b292d03954b2	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/logout", "method": "POST", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "46deed0a-591d-4f35-8e7e-b292d03954b2", "status_code": 200, "completed_at": "2026-02-25T11:05:16.067670253+08:00", "client_request_id": ""}
233	2026-02-25 11:05:16.075757+08	info	http.access	http request completed	590dd8bb-a91b-422e-815e-37801b1d88c8	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/AuthLayout-BLY8cBK0.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "590dd8bb-a91b-422e-815e-37801b1d88c8", "status_code": 200, "completed_at": "2026-02-25T11:05:16.075739605+08:00", "client_request_id": ""}
234	2026-02-25 11:05:16.07577+08	info	http.access	http request completed	ea34a9d9-fbb1-4168-bf17-9f0301bf50ff	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/AuthLayout-D_5JJD4j.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "ea34a9d9-fbb1-4168-bf17-9f0301bf50ff", "status_code": 200, "completed_at": "2026-02-25T11:05:16.075756505+08:00", "client_request_id": ""}
235	2026-02-25 11:05:16.07592+08	info	http.access	http request completed	30135a8d-772f-488e-a79f-5cc6ff645fe7	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/LoginView-Dm2m7DcW.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "30135a8d-772f-488e-a79f-5cc6ff645fe7", "status_code": 200, "completed_at": "2026-02-25T11:05:16.075900904+08:00", "client_request_id": ""}
236	2026-02-25 11:05:16.07603+08	info	http.access	http request completed	21779aa7-815f-4194-a2bb-c308bafa3635	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/LinuxDoOAuthSection.vue_vue_type_script_setup_true_lang-DJujUfeo.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "21779aa7-815f-4194-a2bb-c308bafa3635", "status_code": 200, "completed_at": "2026-02-25T11:05:16.075996103+08:00", "client_request_id": ""}
237	2026-02-25 11:05:16.076098+08	info	http.access	http request completed	abd85161-015b-4b08-b682-cfa2770d6e2d	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/TurnstileWidget-9t9fJkOj.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "abd85161-015b-4b08-b682-cfa2770d6e2d", "status_code": 200, "completed_at": "2026-02-25T11:05:16.076088703+08:00", "client_request_id": ""}
238	2026-02-25 11:05:16.076147+08	info	http.access	http request completed	8b01bdbd-ddfd-40ab-be00-5828256d864d	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/TurnstileWidget-CtZXX_iR.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "8b01bdbd-ddfd-40ab-be00-5828256d864d", "status_code": 200, "completed_at": "2026-02-25T11:05:16.076116803+08:00", "client_request_id": ""}
239	2026-02-25 11:05:16.07767+08	info	http.access	http request completed	540349aa-b3de-4556-8e35-8a29cacfbe91	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/LoginView-CM0iaiMq.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "540349aa-b3de-4556-8e35-8a29cacfbe91", "status_code": 200, "completed_at": "2026-02-25T11:05:16.077336495+08:00", "client_request_id": ""}
240	2026-02-25 11:05:16.09557+08	info	http.access	http request completed	ce526d6e-b830-4b7a-b7be-9e224033ba94	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/settings/public", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 1, "request_id": "ce526d6e-b830-4b7a-b7be-9e224033ba94", "status_code": 200, "completed_at": "2026-02-25T11:05:16.095544988+08:00", "client_request_id": ""}
241	2026-02-25 11:05:32.62052+08	error	stdlog	[LDAP] user search failed identifier=wanghongping: error: code=*** reason="USER_NOT_FOUND" message="user not found" metadata=map[]	\N	\N	\N	\N	\N	\N	{"env": "production", "service": "sub2api", "legacy_stdlog": true}
242	2026-02-25 11:05:32.620788+08	info	http.access	http request completed	45af905d-f9e3-405c-b90f-b3a38073a2f1	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/login", "method": "POST", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 9, "request_id": "45af905d-f9e3-405c-b90f-b3a38073a2f1", "status_code": 401, "completed_at": "2026-02-25T11:05:32.620771637+08:00", "client_request_id": ""}
243	2026-02-25 11:06:30.753106+08	info	http.access	http request completed	cd25f755-bf66-4a6b-ad43-3a603130f5b2	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/vendor-misc-DB0Q8XAf.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "cd25f755-bf66-4a6b-ad43-3a603130f5b2", "status_code": 200, "completed_at": "2026-02-25T11:06:30.753093009+08:00", "client_request_id": ""}
244	2026-02-25 11:06:30.753375+08	info	http.access	http request completed	f92759cc-d4b3-450d-97c6-82d88fd5fc14	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/LocaleSwitcher-CjvPxOhx.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "f92759cc-d4b3-450d-97c6-82d88fd5fc14", "status_code": 200, "completed_at": "2026-02-25T11:06:30.753362007+08:00", "client_request_id": ""}
245	2026-02-25 11:06:30.753397+08	info	http.access	http request completed	80b7afa0-2291-4e30-bed5-842c50bdcf3e	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/index-Dji9Snxu.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "80b7afa0-2291-4e30-bed5-842c50bdcf3e", "status_code": 200, "completed_at": "2026-02-25T11:06:30.753381707+08:00", "client_request_id": ""}
246	2026-02-25 11:06:30.753519+08	info	http.access	http request completed	041ff56e-c292-4252-95b8-faa32fe14e0a	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/AppHeader-NeOcFzPI.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "041ff56e-c292-4252-95b8-faa32fe14e0a", "status_code": 200, "completed_at": "2026-02-25T11:06:30.753508206+08:00", "client_request_id": ""}
247	2026-02-25 11:06:30.753594+08	info	http.access	http request completed	e56790ac-7ca9-4ef4-95d1-cda3878107b9	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/AuthLayout-BLY8cBK0.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "e56790ac-7ca9-4ef4-95d1-cda3878107b9", "status_code": 200, "completed_at": "2026-02-25T11:06:30.753584706+08:00", "client_request_id": ""}
248	2026-02-25 11:06:30.753721+08	info	http.access	http request completed	c5523d4a-9c16-4282-9c98-aedf750d593f	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/TurnstileWidget-CtZXX_iR.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "c5523d4a-9c16-4282-9c98-aedf750d593f", "status_code": 200, "completed_at": "2026-02-25T11:06:30.753712405+08:00", "client_request_id": ""}
249	2026-02-25 11:06:30.758941+08	info	http.access	http request completed	42d6f44e-8b97-4458-b526-a72ed2479dbb	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/LoginView-CM0iaiMq.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "42d6f44e-8b97-4458-b526-a72ed2479dbb", "status_code": 200, "completed_at": "2026-02-25T11:06:30.758926076+08:00", "client_request_id": ""}
250	2026-02-25 11:06:30.760188+08	info	http.access	http request completed	024a5802-a429-4015-bd04-50f03a9d45c9	\N	\N	\N	\N	\N	{"env": "production", "path": "/.well-known/appspecific/com.chrome.devtools.json", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "024a5802-a429-4015-bd04-50f03a9d45c9", "status_code": 200, "completed_at": "2026-02-25T11:06:30.760172969+08:00", "client_request_id": ""}
251	2026-02-25 11:06:36.078872+08	info	http.access	http request completed	643007ae-70cf-45bd-a355-11125e015201	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/login", "method": "POST", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 51, "request_id": "643007ae-70cf-45bd-a355-11125e015201", "status_code": 200, "completed_at": "2026-02-25T11:06:36.078853522+08:00", "client_request_id": ""}
252	2026-02-25 11:06:36.086511+08	info	http.access	http request completed	6b9564b4-1565-4d5f-9ab5-ebe1c498679f	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/subscriptions/active", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "6b9564b4-1565-4d5f-9ab5-ebe1c498679f", "status_code": 200, "completed_at": "2026-02-25T11:06:36.086456178+08:00", "client_request_id": ""}
253	2026-02-25 11:06:36.086638+08	info	http.access	http request completed	bf0ef110-f7d6-4682-9683-9e034eb93e2a	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/usage-BlWL46gW.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "bf0ef110-f7d6-4682-9683-9e034eb93e2a", "status_code": 200, "completed_at": "2026-02-25T11:06:36.086629177+08:00", "client_request_id": ""}
254	2026-02-25 11:06:36.086715+08	info	http.access	http request completed	e2d2263e-25e2-48b2-98c6-2c7104e36402	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/LoadingSpinner-CyStGumC.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "e2d2263e-25e2-48b2-98c6-2c7104e36402", "status_code": 200, "completed_at": "2026-02-25T11:06:36.086702577+08:00", "client_request_id": ""}
255	2026-02-25 11:06:36.08679+08	info	http.access	http request completed	3ea778e8-d2c4-42f3-b383-6bc73169d478	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/DashboardView-DVWIfxM4.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "3ea778e8-d2c4-42f3-b383-6bc73169d478", "status_code": 200, "completed_at": "2026-02-25T11:06:36.086774277+08:00", "client_request_id": ""}
256	2026-02-25 11:06:36.086741+08	info	http.access	http request completed	8e61c5b7-8810-49a1-ae3a-744b8ca46235	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/LoadingSpinner-DT-rtrW_.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "8e61c5b7-8810-49a1-ae3a-744b8ca46235", "status_code": 200, "completed_at": "2026-02-25T11:06:36.086731377+08:00", "client_request_id": ""}
257	2026-02-25 11:06:36.087242+08	info	http.access	http request completed	48cf7b5f-cb32-470a-84c6-b08b300cc2a5	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/DateRangePicker-4QcPOZ3x.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "48cf7b5f-cb32-470a-84c6-b08b300cc2a5", "status_code": 200, "completed_at": "2026-02-25T11:06:36.087221274+08:00", "client_request_id": ""}
258	2026-02-25 11:06:36.094106+08	info	http.access	http request completed	ec4a4a9d-33fa-4b7c-9520-b7d695b98462	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/DateRangePicker-CFGGkPM1.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "ec4a4a9d-33fa-4b7c-9520-b7d695b98462", "status_code": 200, "completed_at": "2026-02-25T11:06:36.094094634+08:00", "client_request_id": ""}
259	2026-02-25 11:06:36.09421+08	info	http.access	http request completed	93ac7051-309a-4e91-b7a4-a3a96b9d4f1b	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/Select-7fPaeC0I.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "93ac7051-309a-4e91-b7a4-a3a96b9d4f1b", "status_code": 200, "completed_at": "2026-02-25T11:06:36.094197734+08:00", "client_request_id": ""}
260	2026-02-25 11:06:36.094274+08	info	http.access	http request completed	555daa72-ed68-430e-8725-f1cf6437b92b	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/Select-M2m3gzLX.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "555daa72-ed68-430e-8725-f1cf6437b92b", "status_code": 200, "completed_at": "2026-02-25T11:06:36.094262733+08:00", "client_request_id": ""}
261	2026-02-25 11:06:36.096175+08	info	http.access	http request completed	217dbf3b-248a-4d09-af37-1763c3ed10f8	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/TokenUsageTrend.vue_vue_type_script_setup_true_lang-DnDbESHW.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "217dbf3b-248a-4d09-af37-1763c3ed10f8", "status_code": 200, "completed_at": "2026-02-25T11:06:36.096160923+08:00", "client_request_id": ""}
262	2026-02-25 11:06:36.096387+08	info	http.access	http request completed	dc7bed58-8051-45af-9de8-70c24d60fc15	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/EmptyState.vue_vue_type_script_setup_true_lang-BuIi38rv.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "dc7bed58-8051-45af-9de8-70c24d60fc15", "status_code": 200, "completed_at": "2026-02-25T11:06:36.096372721+08:00", "client_request_id": ""}
263	2026-02-25 11:06:36.096394+08	info	http.access	http request completed	a479ad9e-1535-4e50-be55-dcd39621b21d	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/vendor-chart-BqAhThnj.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "a479ad9e-1535-4e50-be55-dcd39621b21d", "status_code": 200, "completed_at": "2026-02-25T11:06:36.096380921+08:00", "client_request_id": ""}
264	2026-02-25 11:06:36.136107+08	info	http.access	http request completed	2d86d9d2-d43e-4052-874b-81f52a96998a	\N	\N	\N	\N	\N	{"env": "production", "path": "/logo.png", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "2d86d9d2-d43e-4052-874b-81f52a96998a", "status_code": 200, "completed_at": "2026-02-25T11:06:36.136082292+08:00", "client_request_id": ""}
265	2026-02-25 11:06:36.139913+08	info	http.access	http request completed	9ae261ec-f758-43c3-85b6-7c6e6467a3e2	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage/dashboard/trend", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 4, "request_id": "9ae261ec-f758-43c3-85b6-7c6e6467a3e2", "status_code": 200, "completed_at": "2026-02-25T11:06:36.13988747+08:00", "client_request_id": ""}
266	2026-02-25 11:06:36.139921+08	info	http.access	http request completed	1b8cd0f8-d950-4001-b7eb-e5abe94e4b80	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage/dashboard/models", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 4, "request_id": "1b8cd0f8-d950-4001-b7eb-e5abe94e4b80", "status_code": 200, "completed_at": "2026-02-25T11:06:36.13990337+08:00", "client_request_id": ""}
267	2026-02-25 11:06:36.140219+08	info	http.access	http request completed	e6a738f0-bfcd-43c9-ade9-e5435782d468	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 4, "request_id": "e6a738f0-bfcd-43c9-ade9-e5435782d468", "status_code": 200, "completed_at": "2026-02-25T11:06:36.140204769+08:00", "client_request_id": ""}
268	2026-02-25 11:06:36.141535+08	info	http.access	http request completed	63d0894c-7833-4920-88bd-6adc1df8a610	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/announcements", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 5, "request_id": "63d0894c-7833-4920-88bd-6adc1df8a610", "status_code": 200, "completed_at": "2026-02-25T11:06:36.141519261+08:00", "client_request_id": ""}
269	2026-02-25 11:06:36.143977+08	info	http.access	http request completed	8b06ced9-978d-455b-91ed-84189f6e36fd	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 7, "request_id": "8b06ced9-978d-455b-91ed-84189f6e36fd", "status_code": 200, "completed_at": "2026-02-25T11:06:36.143932547+08:00", "client_request_id": ""}
270	2026-02-25 11:06:36.147929+08	info	http.access	http request completed	8bd1c0f3-a883-4acd-a1bc-4080b7f7a674	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/KeysView-CCSOZ5fG.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "8bd1c0f3-a883-4acd-a1bc-4080b7f7a674", "status_code": 200, "completed_at": "2026-02-25T11:06:36.147904224+08:00", "client_request_id": ""}
271	2026-02-25 11:06:36.151045+08	info	http.access	http request completed	957d4eea-b1b1-42d4-9709-ae6b52c0509b	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/TablePageLayout-eKTo0RsV.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "957d4eea-b1b1-42d4-9709-ae6b52c0509b", "status_code": 200, "completed_at": "2026-02-25T11:06:36.151020206+08:00", "client_request_id": ""}
272	2026-02-25 11:06:36.151327+08	info	http.access	http request completed	05ea0be3-0cfb-43bf-9063-3b8dc22a0fc4	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/keys-_v9ZnNui.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "05ea0be3-0cfb-43bf-9063-3b8dc22a0fc4", "status_code": 200, "completed_at": "2026-02-25T11:06:36.151314704+08:00", "client_request_id": ""}
273	2026-02-25 11:06:36.151387+08	info	http.access	http request completed	083287ed-42b2-467a-b933-a28db4234a9e	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/TablePageLayout-BIThKX5Z.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "083287ed-42b2-467a-b933-a28db4234a9e", "status_code": 200, "completed_at": "2026-02-25T11:06:36.151371304+08:00", "client_request_id": ""}
274	2026-02-25 11:06:36.151691+08	info	http.access	http request completed	ca25a6ef-0583-4a16-950a-62ec9ffeaeb8	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/DataTable-BSDXutJh.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "ca25a6ef-0583-4a16-950a-62ec9ffeaeb8", "status_code": 200, "completed_at": "2026-02-25T11:06:36.151675402+08:00", "client_request_id": ""}
275	2026-02-25 11:06:36.164523+08	info	http.access	http request completed	7265c621-166f-434a-9232-3dc087d2cede	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/DataTable-wk4w1kiu.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "7265c621-166f-434a-9232-3dc087d2cede", "status_code": 200, "completed_at": "2026-02-25T11:06:36.164511028+08:00", "client_request_id": ""}
276	2026-02-25 11:06:36.165132+08	info	http.access	http request completed	f98c6a4f-2631-436c-897d-618f510dd54a	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/Pagination-DtcDDVEA.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "f98c6a4f-2631-436c-897d-618f510dd54a", "status_code": 200, "completed_at": "2026-02-25T11:06:36.165119025+08:00", "client_request_id": ""}
277	2026-02-25 11:06:36.168068+08	info	http.access	http request completed	9d1b90f7-27d0-4b01-b109-5c007afacfc5	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/GroupBadge.vue_vue_type_script_setup_true_lang-Cej1HtUK.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "9d1b90f7-27d0-4b01-b109-5c007afacfc5", "status_code": 200, "completed_at": "2026-02-25T11:06:36.168009308+08:00", "client_request_id": ""}
278	2026-02-25 11:06:36.168084+08	info	http.access	http request completed	611344f0-fa37-4fc6-bcd0-27ae7d754b0b	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/Pagination-Cy120BZx.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "611344f0-fa37-4fc6-bcd0-27ae7d754b0b", "status_code": 200, "completed_at": "2026-02-25T11:06:36.168073208+08:00", "client_request_id": ""}
279	2026-02-25 11:06:36.168174+08	info	http.access	http request completed	e9d0855c-8102-4637-b3da-05e19232b6ce	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/PlatformIcon.vue_vue_type_script_setup_true_lang-DDJ5Ol8Z.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "e9d0855c-8102-4637-b3da-05e19232b6ce", "status_code": 200, "completed_at": "2026-02-25T11:06:36.168160707+08:00", "client_request_id": ""}
280	2026-02-25 11:06:36.168123+08	info	http.access	http request completed	fd13e66a-fbf8-4945-b1d9-6f6a7c3152ab	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/ConfirmDialog.vue_vue_type_script_setup_true_lang-Brt6MSpz.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "fd13e66a-fbf8-4945-b1d9-6f6a7c3152ab", "status_code": 200, "completed_at": "2026-02-25T11:06:36.168106208+08:00", "client_request_id": ""}
281	2026-02-25 11:06:36.172033+08	info	http.access	http request completed	1d71b8b7-1db9-4546-9cf3-45ab54951154	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/GroupOptionItem.vue_vue_type_script_setup_true_lang-DJgQlkUJ.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "1d71b8b7-1db9-4546-9cf3-45ab54951154", "status_code": 200, "completed_at": "2026-02-25T11:06:36.172017085+08:00", "client_request_id": ""}
282	2026-02-25 11:06:36.172235+08	info	http.access	http request completed	9b359bef-b4ea-4d9c-9c0c-5bb76bae891c	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/UsageView-WokokQ3Q.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "9b359bef-b4ea-4d9c-9c0c-5bb76bae891c", "status_code": 200, "completed_at": "2026-02-25T11:06:36.172214884+08:00", "client_request_id": ""}
283	2026-02-25 11:06:36.179056+08	info	http.access	http request completed	181c3fc1-d43e-4abb-a4da-220fe493eaec	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage/dashboard/stats", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 5, "request_id": "181c3fc1-d43e-4abb-a4da-220fe493eaec", "status_code": 200, "completed_at": "2026-02-25T11:06:36.179037045+08:00", "client_request_id": ""}
284	2026-02-25 11:06:40.609513+08	info	http.access	http request completed	94771df3-370b-4858-915f-44f798533394	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/settings/stream-timeout", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "94771df3-370b-4858-915f-44f798533394", "status_code": 200, "completed_at": "2026-02-25T11:06:40.609476598+08:00", "client_request_id": ""}
285	2026-02-25 11:06:40.609589+08	info	http.access	http request completed	5aa0a536-8537-4c04-937a-4f705f6fd8ac	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/settings/admin-api-key", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "5aa0a536-8537-4c04-937a-4f705f6fd8ac", "status_code": 200, "completed_at": "2026-02-25T11:06:40.609573297+08:00", "client_request_id": ""}
286	2026-02-25 11:06:40.610278+08	info	http.access	http request completed	ba0dd0ba-801f-44dc-abf5-bdbbd84e7447	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/settings", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "ba0dd0ba-801f-44dc-abf5-bdbbd84e7447", "status_code": 200, "completed_at": "2026-02-25T11:06:40.610253993+08:00", "client_request_id": ""}
287	2026-02-25 11:06:40.614553+08	info	http.access	http request completed	2e26c70c-e261-433b-af23-d164783f174e	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/announcements", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 7, "request_id": "2e26c70c-e261-433b-af23-d164783f174e", "status_code": 200, "completed_at": "2026-02-25T11:06:40.614522068+08:00", "client_request_id": ""}
288	2026-02-25 11:06:56.448511+08	info	http.access	http request completed	9207cf86-0074-4695-bef1-71eb31a185d5	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/ModelDistributionChart.vue_vue_type_script_setup_true_lang-C4GZUv6g.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "9207cf86-0074-4695-bef1-71eb31a185d5", "status_code": 200, "completed_at": "2026-02-25T11:06:56.44850091+08:00", "client_request_id": ""}
289	2026-02-25 11:06:56.448577+08	info	http.access	http request completed	bb4ce694-eaf1-4f3c-ae4c-5b39f5fd7da9	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/DashboardView-Ai2Uq9NG.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "bb4ce694-eaf1-4f3c-ae4c-5b39f5fd7da9", "status_code": 200, "completed_at": "2026-02-25T11:06:56.44856881+08:00", "client_request_id": ""}
290	2026-02-25 11:06:56.467766+08	info	http.access	http request completed	70870c2b-7978-4fa7-9be8-b585f6fef965	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/dashboard/models", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "70870c2b-7978-4fa7-9be8-b585f6fef965", "status_code": 200, "completed_at": "2026-02-25T11:06:56.4677265+08:00", "client_request_id": ""}
291	2026-02-25 11:06:56.468223+08	info	http.access	http request completed	08dbb859-1b82-4836-862c-ec426a4e3342	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/dashboard/trend", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "08dbb859-1b82-4836-862c-ec426a4e3342", "status_code": 200, "completed_at": "2026-02-25T11:06:56.468200097+08:00", "client_request_id": ""}
292	2026-02-25 11:06:56.468278+08	info	http.access	http request completed	7680b37d-d042-4353-a61c-3809463c18fd	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/dashboard/users-trend", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "7680b37d-d042-4353-a61c-3809463c18fd", "status_code": 200, "completed_at": "2026-02-25T11:06:56.468262697+08:00", "client_request_id": ""}
293	2026-02-25 11:06:56.469328+08	info	http.access	http request completed	cefeac34-dc0c-44ec-bffc-7e61c3234b56	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/announcements", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 4, "request_id": "cefeac34-dc0c-44ec-bffc-7e61c3234b56", "status_code": 200, "completed_at": "2026-02-25T11:06:56.469306291+08:00", "client_request_id": ""}
294	2026-02-25 11:06:56.473006+08	info	http.access	http request completed	6b6f8d95-0693-4ae7-a92d-764a7bb22a4b	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/dashboard/stats", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 8, "request_id": "6b6f8d95-0693-4ae7-a92d-764a7bb22a4b", "status_code": 200, "completed_at": "2026-02-25T11:06:56.472979969+08:00", "client_request_id": ""}
295	2026-02-25 11:06:56.504216+08	info	http.access	http request completed	9737cd53-b70e-4262-984d-d9e795c12349	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/GroupSelector.vue_vue_type_script_setup_true_lang-CcNVQhCX.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "9737cd53-b70e-4262-984d-d9e795c12349", "status_code": 200, "completed_at": "2026-02-25T11:06:56.504203789+08:00", "client_request_id": ""}
296	2026-02-25 11:06:56.504342+08	info	http.access	http request completed	4c8a41b2-48f6-4eb1-b8b8-8ad611ae2c9d	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/vendor-ui-CAt8eLho.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "4c8a41b2-48f6-4eb1-b8b8-8ad611ae2c9d", "status_code": 200, "completed_at": "2026-02-25T11:06:56.504325089+08:00", "client_request_id": ""}
297	2026-02-25 11:06:56.504048+08	info	http.access	http request completed	400432d9-e5a9-488b-88e1-77b5c7e40efd	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/AccountsView-HVqLN203.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "400432d9-e5a9-488b-88e1-77b5c7e40efd", "status_code": 200, "completed_at": "2026-02-25T11:06:56.50402519+08:00", "client_request_id": ""}
298	2026-02-25 11:06:56.504669+08	info	http.access	http request completed	12eab27f-c882-4d39-b884-1beb3323c21a	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/stableObjectKey-DullU5Fx.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "12eab27f-c882-4d39-b884-1beb3323c21a", "status_code": 200, "completed_at": "2026-02-25T11:06:56.504661487+08:00", "client_request_id": ""}
299	2026-02-25 11:06:56.504711+08	info	http.access	http request completed	8f38ff47-dd8c-4672-ac16-fb8a9bf4dc25	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/AccountsView-D1GA-FAQ.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "8f38ff47-dd8c-4672-ac16-fb8a9bf4dc25", "status_code": 200, "completed_at": "2026-02-25T11:06:56.504697887+08:00", "client_request_id": ""}
300	2026-02-25 11:06:56.504843+08	info	http.access	http request completed	d4ea45df-c68c-4c20-b01c-b919409fd169	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/PlatformTypeBadge.vue_vue_type_script_setup_true_lang-C0GL-GYg.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "d4ea45df-c68c-4c20-b01c-b919409fd169", "status_code": 200, "completed_at": "2026-02-25T11:06:56.504836186+08:00", "client_request_id": ""}
301	2026-02-25 11:06:56.51395+08	info	http.access	http request completed	40f50e23-25f8-4155-a905-d7814be66be0	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/UsersView-qOd5hN3-.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "40f50e23-25f8-4155-a905-d7814be66be0", "status_code": 200, "completed_at": "2026-02-25T11:06:56.513938933+08:00", "client_request_id": ""}
302	2026-02-25 11:06:56.51488+08	info	http.access	http request completed	3830e9c7-8e03-4f87-8839-351e865b5f93	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/UsersView-D-m7HAka.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "3830e9c7-8e03-4f87-8839-351e865b5f93", "status_code": 200, "completed_at": "2026-02-25T11:06:56.514854328+08:00", "client_request_id": ""}
303	2026-02-25 11:07:14.748642+08	info	http.access	http request completed	c9ed62a7-b8c3-4be8-9625-ad0f8018ea51	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/settings/stream-timeout", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 1, "request_id": "c9ed62a7-b8c3-4be8-9625-ad0f8018ea51", "status_code": 200, "completed_at": "2026-02-25T11:07:14.748601523+08:00", "client_request_id": ""}
304	2026-02-25 11:07:14.748649+08	info	http.access	http request completed	820e7192-9b43-4c9c-8da8-af3b0879f4b7	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/settings/admin-api-key", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "820e7192-9b43-4c9c-8da8-af3b0879f4b7", "status_code": 200, "completed_at": "2026-02-25T11:07:14.748632722+08:00", "client_request_id": ""}
305	2026-02-25 11:07:14.749368+08	info	http.access	http request completed	7767af60-0ffd-43f7-ac7c-cdbe9d366e48	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/settings", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "7767af60-0ffd-43f7-ac7c-cdbe9d366e48", "status_code": 200, "completed_at": "2026-02-25T11:07:14.749351718+08:00", "client_request_id": ""}
306	2026-02-25 11:07:14.751551+08	info	http.access	http request completed	82fa02f5-188f-4ecf-8c10-13eaf37a0363	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/announcements", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 5, "request_id": "82fa02f5-188f-4ecf-8c10-13eaf37a0363", "status_code": 200, "completed_at": "2026-02-25T11:07:14.751513006+08:00", "client_request_id": ""}
307	2026-02-25 11:07:36.087223+08	info	http.access	http request completed	beac4db2-5d4f-4b24-a3e7-6ade183ea320	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "beac4db2-5d4f-4b24-a3e7-6ade183ea320", "status_code": 200, "completed_at": "2026-02-25T11:07:36.087204445+08:00", "client_request_id": ""}
308	2026-02-25 11:08:36.085148+08	info	http.access	http request completed	1491344f-3caf-4f90-a4dc-eee046db0d0b	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "1491344f-3caf-4f90-a4dc-eee046db0d0b", "status_code": 200, "completed_at": "2026-02-25T11:08:36.085134919+08:00", "client_request_id": ""}
309	2026-02-25 11:09:36.099279+08	info	http.access	http request completed	90761f2a-1a6e-4527-8e96-84bc6df9bb0c	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "90761f2a-1a6e-4527-8e96-84bc6df9bb0c", "status_code": 200, "completed_at": "2026-02-25T11:09:36.099260932+08:00", "client_request_id": ""}
310	2026-02-25 11:10:36.085592+08	info	http.access	http request completed	21db9a9f-6823-4391-9562-a17c70220930	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "21db9a9f-6823-4391-9562-a17c70220930", "status_code": 200, "completed_at": "2026-02-25T11:10:36.08557547+08:00", "client_request_id": ""}
311	2026-02-25 11:11:36.100715+08	info	http.access	http request completed	afc142a5-9211-4d69-a33b-d3ed838d08c2	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "afc142a5-9211-4d69-a33b-d3ed838d08c2", "status_code": 200, "completed_at": "2026-02-25T11:11:36.100701029+08:00", "client_request_id": ""}
312	2026-02-25 11:11:36.101094+08	info	http.access	http request completed	bcf26923-fadb-4a6e-8a8e-81d1910008c2	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/subscriptions/active", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "bcf26923-fadb-4a6e-8a8e-81d1910008c2", "status_code": 200, "completed_at": "2026-02-25T11:11:36.101082027+08:00", "client_request_id": ""}
313	2026-02-25 11:12:36.122022+08	info	http.access	http request completed	e8100e48-38c1-4203-a4f4-b7bc04c2dcca	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 4, "request_id": "e8100e48-38c1-4203-a4f4-b7bc04c2dcca", "status_code": 200, "completed_at": "2026-02-25T11:12:36.121949347+08:00", "client_request_id": ""}
314	2026-02-25 11:13:16.578152+08	warn	stdlog	Warning: server.trusted_proxies is empty in release mode; client IP trust chain is disabled	\N	\N	\N	\N	\N	\N	{"env": "production", "service": "sub2api", "legacy_stdlog": true}
315	2026-02-25 11:13:16.5782+08	warn	stdlog	Warning: CORS allowed_origins not configured; cross-origin requests will be rejected.	\N	\N	\N	\N	\N	\N	{"env": "production", "service": "sub2api", "legacy_stdlog": true}
316	2026-02-25 11:13:35.390194+08	info	http.access	http request completed	672d205a-360a-408c-9b95-e314c71a1755	\N	\N	\N	\N	\N	{"env": "production", "path": "/admin/settings", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 1, "request_id": "672d205a-360a-408c-9b95-e314c71a1755", "status_code": 200, "completed_at": "2026-02-25T11:13:35.390160899+08:00", "client_request_id": ""}
317	2026-02-25 11:13:35.415697+08	info	http.access	http request completed	ad736355-3249-437d-a152-428462f8e1ef	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/index-CkKnxzIb.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "ad736355-3249-437d-a152-428462f8e1ef", "status_code": 200, "completed_at": "2026-02-25T11:13:35.415665161+08:00", "client_request_id": ""}
318	2026-02-25 11:13:35.416091+08	info	http.access	http request completed	0adadb61-52a9-4b71-86ca-28d482fb6c24	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/vendor-vue-4WNFgugS.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "0adadb61-52a9-4b71-86ca-28d482fb6c24", "status_code": 200, "completed_at": "2026-02-25T11:13:35.416069659+08:00", "client_request_id": ""}
319	2026-02-25 11:13:35.418288+08	info	http.access	http request completed	deebe60d-981b-412a-acb8-6c4e4527c02c	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/vendor-misc-DB0Q8XAf.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "deebe60d-981b-412a-acb8-6c4e4527c02c", "status_code": 200, "completed_at": "2026-02-25T11:13:35.418270447+08:00", "client_request_id": ""}
320	2026-02-25 11:13:35.419059+08	info	http.access	http request completed	0f182514-ee02-4210-ac76-ae35a7dd92ef	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/index-Dji9Snxu.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "0f182514-ee02-4210-ac76-ae35a7dd92ef", "status_code": 200, "completed_at": "2026-02-25T11:13:35.419040843+08:00", "client_request_id": ""}
321	2026-02-25 11:13:35.419751+08	info	http.access	http request completed	8b5a4f43-f756-4da2-913a-a48de37ce310	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/vendor-misc-NmuJm1mp.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "8b5a4f43-f756-4da2-913a-a48de37ce310", "status_code": 200, "completed_at": "2026-02-25T11:13:35.419728639+08:00", "client_request_id": ""}
322	2026-02-25 11:13:35.420616+08	info	http.access	http request completed	5c0d4142-03b4-41f0-b3f2-5edcfae6bb6a	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/vendor-i18n-CF5oKjnm.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "5c0d4142-03b4-41f0-b3f2-5edcfae6bb6a", "status_code": 200, "completed_at": "2026-02-25T11:13:35.420606034+08:00", "client_request_id": ""}
323	2026-02-25 11:13:35.505469+08	info	http.access	http request completed	56c02887-98c8-4ddf-946e-f81d018c88ef	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/zh-joyDK6VH.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "56c02887-98c8-4ddf-946e-f81d018c88ef", "status_code": 200, "completed_at": "2026-02-25T11:13:35.505446175+08:00", "client_request_id": ""}
324	2026-02-25 11:13:35.517717+08	info	http.access	http request completed	a3218e18-f96a-4c8d-a5b2-ddd597020e2d	\N	\N	\N	\N	\N	{"env": "production", "path": "/logo.png", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "a3218e18-f96a-4c8d-a5b2-ddd597020e2d", "status_code": 200, "completed_at": "2026-02-25T11:13:35.517694209+08:00", "client_request_id": ""}
325	2026-02-25 11:13:35.527807+08	info	http.access	http request completed	4761d237-64c3-4a76-8c58-85814335e5e9	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/SettingsView-59zWuNEo.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "4761d237-64c3-4a76-8c58-85814335e5e9", "status_code": 200, "completed_at": "2026-02-25T11:13:35.527786954+08:00", "client_request_id": ""}
326	2026-02-25 11:13:35.528014+08	info	http.access	http request completed	bbe47271-fe51-4543-9ff5-ef534432023e	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/AppLayout.vue_vue_type_script_setup_true_lang-CbvznAXW.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "bbe47271-fe51-4543-9ff5-ef534432023e", "status_code": 200, "completed_at": "2026-02-25T11:13:35.527999353+08:00", "client_request_id": ""}
327	2026-02-25 11:13:35.530455+08	info	http.access	http request completed	b7457741-9c80-4f45-94a7-2a9d64bc950e	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/useClipboard-DfSApw15.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "b7457741-9c80-4f45-94a7-2a9d64bc950e", "status_code": 200, "completed_at": "2026-02-25T11:13:35.53044464+08:00", "client_request_id": ""}
328	2026-02-25 11:13:35.530551+08	info	http.access	http request completed	f7d6b40a-7d0c-48d3-adca-a8e1bcfde7f6	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/LocaleSwitcher-CjvPxOhx.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "f7d6b40a-7d0c-48d3-adca-a8e1bcfde7f6", "status_code": 200, "completed_at": "2026-02-25T11:13:35.530537939+08:00", "client_request_id": ""}
329	2026-02-25 11:13:35.530464+08	info	http.access	http request completed	c0006ce0-feab-40fd-9139-5d178a97265f	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/LocaleSwitcher-BaVz3FTM.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "c0006ce0-feab-40fd-9139-5d178a97265f", "status_code": 200, "completed_at": "2026-02-25T11:13:35.53044924+08:00", "client_request_id": ""}
330	2026-02-25 11:13:35.532434+08	info	http.access	http request completed	ad096db7-50e7-4bd8-9abf-96b5a233bf19	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/AppHeader-NeOcFzPI.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "ad096db7-50e7-4bd8-9abf-96b5a233bf19", "status_code": 200, "completed_at": "2026-02-25T11:13:35.532412029+08:00", "client_request_id": ""}
331	2026-02-25 11:13:35.534814+08	info	http.access	http request completed	af87be5f-1555-44d6-8cc9-64454d3806ed	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 7, "request_id": "af87be5f-1555-44d6-8cc9-64454d3806ed", "status_code": 200, "completed_at": "2026-02-25T11:13:35.534791116+08:00", "client_request_id": ""}
332	2026-02-25 11:13:35.535122+08	info	http.access	http request completed	9c04a1a6-461c-48ae-8cf4-80f3b0c10f1b	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/Toggle.vue_vue_type_script_setup_true_lang-B0FKZlYT.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "9c04a1a6-461c-48ae-8cf4-80f3b0c10f1b", "status_code": 200, "completed_at": "2026-02-25T11:13:35.535111315+08:00", "client_request_id": ""}
333	2026-02-25 11:13:35.570608+08	info	http.access	http request completed	103702ac-3b94-4f28-bad3-fadc1f29ac3b	\N	\N	\N	\N	\N	{"env": "production", "path": "/logo.png", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "103702ac-3b94-4f28-bad3-fadc1f29ac3b", "status_code": 200, "completed_at": "2026-02-25T11:13:35.570586823+08:00", "client_request_id": ""}
334	2026-02-25 11:13:35.575367+08	info	http.access	http request completed	9cc2997c-45ca-4c92-a2e0-865076f53a57	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/subscriptions/active", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 4, "request_id": "9cc2997c-45ca-4c92-a2e0-865076f53a57", "status_code": 200, "completed_at": "2026-02-25T11:13:35.575340897+08:00", "client_request_id": ""}
335	2026-02-25 11:13:35.582444+08	info	http.access	http request completed	99ec35f0-5a6e-44c0-9c6d-ede188d23dbe	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/settings", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 5, "request_id": "99ec35f0-5a6e-44c0-9c6d-ede188d23dbe", "status_code": 200, "completed_at": "2026-02-25T11:13:35.582420059+08:00", "client_request_id": ""}
336	2026-02-25 11:13:35.583315+08	info	http.access	http request completed	cafd5449-286c-4241-b082-8ad7d9d4b25a	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/settings/admin-api-key", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 5, "request_id": "cafd5449-286c-4241-b082-8ad7d9d4b25a", "status_code": 200, "completed_at": "2026-02-25T11:13:35.583292454+08:00", "client_request_id": ""}
337	2026-02-25 11:13:35.584215+08	info	http.access	http request completed	2cf5edc9-a02f-4e48-90e9-adadf3ce4c80	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/settings/stream-timeout", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 5, "request_id": "2cf5edc9-a02f-4e48-90e9-adadf3ce4c80", "status_code": 200, "completed_at": "2026-02-25T11:13:35.584204349+08:00", "client_request_id": ""}
338	2026-02-25 11:13:35.586078+08	info	http.access	http request completed	27eb9140-5d2f-4301-917b-f37be97bb354	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/settings", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "27eb9140-5d2f-4301-917b-f37be97bb354", "status_code": 200, "completed_at": "2026-02-25T11:13:35.586059039+08:00", "client_request_id": ""}
339	2026-02-25 11:13:35.586197+08	info	http.access	http request completed	98170f67-000e-4129-977d-7c463adc9163	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/announcements", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 8, "request_id": "98170f67-000e-4129-977d-7c463adc9163", "status_code": 200, "completed_at": "2026-02-25T11:13:35.586182339+08:00", "client_request_id": ""}
340	2026-02-25 11:13:36.209992+08	info	http.access	http request completed	a14a3f19-3bf0-4e4a-9aee-982f017f9652	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/system/check-updates", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 632, "request_id": "a14a3f19-3bf0-4e4a-9aee-982f017f9652", "status_code": 200, "completed_at": "2026-02-25T11:13:36.209973365+08:00", "client_request_id": ""}
341	2026-02-25 11:13:38.348943+08	info	http.access	http request completed	58fd079e-cb41-4e63-bd13-53af68218352	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/logout", "method": "POST", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "58fd079e-cb41-4e63-bd13-53af68218352", "status_code": 200, "completed_at": "2026-02-25T11:13:38.348928028+08:00", "client_request_id": ""}
342	2026-02-25 11:13:38.364439+08	info	http.access	http request completed	76350ac1-5ae1-47e9-bf2b-44897b73b568	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/TurnstileWidget-CsDyAChT.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "76350ac1-5ae1-47e9-bf2b-44897b73b568", "status_code": 200, "completed_at": "2026-02-25T11:13:38.364425645+08:00", "client_request_id": ""}
343	2026-02-25 11:13:38.364515+08	info	http.access	http request completed	db4f878c-9aeb-488b-9bbe-a4489666e686	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/AuthLayout-DuqqvlHK.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "db4f878c-9aeb-488b-9bbe-a4489666e686", "status_code": 200, "completed_at": "2026-02-25T11:13:38.364506444+08:00", "client_request_id": ""}
344	2026-02-25 11:13:38.36454+08	info	http.access	http request completed	85321eaf-2061-44cf-ae55-d58421d412a0	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/LoginView-sMz7fVWw.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "85321eaf-2061-44cf-ae55-d58421d412a0", "status_code": 200, "completed_at": "2026-02-25T11:13:38.364528444+08:00", "client_request_id": ""}
350	2026-02-25 11:13:49.005231+08	error	stdlog	[LDAP] user search failed identifier=wanghongping: error: code=*** reason="USER_NOT_FOUND" message="user not found" metadata=map[]	\N	\N	\N	\N	\N	\N	{"env": "production", "service": "sub2api", "legacy_stdlog": true}
345	2026-02-25 11:13:38.364454+08	info	http.access	http request completed	795979f0-57c7-4c60-8134-40b87d4f89e2	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/AuthLayout-BLY8cBK0.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "795979f0-57c7-4c60-8134-40b87d4f89e2", "status_code": 200, "completed_at": "2026-02-25T11:13:38.364447244+08:00", "client_request_id": ""}
346	2026-02-25 11:13:38.364469+08	info	http.access	http request completed	e130d03d-98dd-4a33-9740-0f22f3a94dae	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/TurnstileWidget-CtZXX_iR.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "e130d03d-98dd-4a33-9740-0f22f3a94dae", "status_code": 200, "completed_at": "2026-02-25T11:13:38.364461444+08:00", "client_request_id": ""}
347	2026-02-25 11:13:38.364641+08	info	http.access	http request completed	2671c66d-cd8c-4e3a-bb6c-45ac3f7d0178	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/LinuxDoOAuthSection.vue_vue_type_script_setup_true_lang-DJujUfeo.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "2671c66d-cd8c-4e3a-bb6c-45ac3f7d0178", "status_code": 200, "completed_at": "2026-02-25T11:13:38.364631343+08:00", "client_request_id": ""}
348	2026-02-25 11:13:38.366161+08	info	http.access	http request completed	173b8c58-99b1-4c2d-8bd1-cf3c2d9b0684	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/LoginView-CM0iaiMq.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "173b8c58-99b1-4c2d-8bd1-cf3c2d9b0684", "status_code": 200, "completed_at": "2026-02-25T11:13:38.366155235+08:00", "client_request_id": ""}
349	2026-02-25 11:13:38.380824+08	info	http.access	http request completed	c5a78dfa-82b8-4ffe-9bfd-0f339984070b	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/settings/public", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 1, "request_id": "c5a78dfa-82b8-4ffe-9bfd-0f339984070b", "status_code": 200, "completed_at": "2026-02-25T11:13:38.380800857+08:00", "client_request_id": ""}
351	2026-02-25 11:13:49.005484+08	info	http.access	http request completed	b7ac983c-d5fd-4136-a2e3-ec01f312b547	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/login", "method": "POST", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 9, "request_id": "b7ac983c-d5fd-4136-a2e3-ec01f312b547", "status_code": 401, "completed_at": "2026-02-25T11:13:49.005471752+08:00", "client_request_id": ""}
352	2026-02-25 11:13:56.002728+08	info	http.access	http request completed	50b380ed-38e4-416d-88e7-9464f5c474fa	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/login", "method": "POST", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 51, "request_id": "50b380ed-38e4-416d-88e7-9464f5c474fa", "status_code": 200, "completed_at": "2026-02-25T11:13:56.002712828+08:00", "client_request_id": ""}
353	2026-02-25 11:13:56.009485+08	info	http.access	http request completed	4834f57e-f0cb-492f-b224-5d7c5ddcfb58	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/usage-DjeCvF1i.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "4834f57e-f0cb-492f-b224-5d7c5ddcfb58", "status_code": 200, "completed_at": "2026-02-25T11:13:56.009471791+08:00", "client_request_id": ""}
354	2026-02-25 11:13:56.009485+08	info	http.access	http request completed	bc20acc6-f5d2-47d5-8ef5-42a328378afc	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/LoadingSpinner-DI27EpD8.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "bc20acc6-f5d2-47d5-8ef5-42a328378afc", "status_code": 200, "completed_at": "2026-02-25T11:13:56.009470691+08:00", "client_request_id": ""}
355	2026-02-25 11:13:56.009651+08	info	http.access	http request completed	fcc901c2-41fe-4667-954d-5d475f655883	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/DashboardView-DpyOZDdn.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "fcc901c2-41fe-4667-954d-5d475f655883", "status_code": 200, "completed_at": "2026-02-25T11:13:56.00963649+08:00", "client_request_id": ""}
356	2026-02-25 11:13:56.009932+08	info	http.access	http request completed	b57de27e-39cf-4509-b0e9-d02a95591efa	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/DateRangePicker-WAZB4rcB.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "b57de27e-39cf-4509-b0e9-d02a95591efa", "status_code": 200, "completed_at": "2026-02-25T11:13:56.009919189+08:00", "client_request_id": ""}
357	2026-02-25 11:13:56.009968+08	info	http.access	http request completed	4391f96d-6a7d-4190-9e7e-ff47447e266c	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/Select-C5iZj_mq.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "4391f96d-6a7d-4190-9e7e-ff47447e266c", "status_code": 200, "completed_at": "2026-02-25T11:13:56.009950288+08:00", "client_request_id": ""}
358	2026-02-25 11:13:56.010569+08	info	http.access	http request completed	ddd005fb-5943-4b1b-bf85-e04cda45452c	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/subscriptions/active", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "ddd005fb-5943-4b1b-bf85-e04cda45452c", "status_code": 200, "completed_at": "2026-02-25T11:13:56.010552685+08:00", "client_request_id": ""}
359	2026-02-25 11:13:56.011603+08	info	http.access	http request completed	b9760dd4-db89-4141-9ae1-7934b9ddb050	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/LoadingSpinner-DT-rtrW_.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "b9760dd4-db89-4141-9ae1-7934b9ddb050", "status_code": 200, "completed_at": "2026-02-25T11:13:56.011594179+08:00", "client_request_id": ""}
360	2026-02-25 11:13:56.011848+08	info	http.access	http request completed	252b23f1-535a-4587-85f0-4b3478e27fed	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/DateRangePicker-CFGGkPM1.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "252b23f1-535a-4587-85f0-4b3478e27fed", "status_code": 200, "completed_at": "2026-02-25T11:13:56.011839778+08:00", "client_request_id": ""}
361	2026-02-25 11:13:56.011911+08	info	http.access	http request completed	eb6db5f7-0f8d-44a9-b3e5-e5450f202edb	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/Select-7fPaeC0I.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "eb6db5f7-0f8d-44a9-b3e5-e5450f202edb", "status_code": 200, "completed_at": "2026-02-25T11:13:56.011898678+08:00", "client_request_id": ""}
362	2026-02-25 11:13:56.014529+08	info	http.access	http request completed	2838359e-9228-4d0f-86b2-3ce4ff1d2429	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/EmptyState.vue_vue_type_script_setup_true_lang-BCx0NwKs.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "2838359e-9228-4d0f-86b2-3ce4ff1d2429", "status_code": 200, "completed_at": "2026-02-25T11:13:56.014517063+08:00", "client_request_id": ""}
363	2026-02-25 11:13:56.014534+08	info	http.access	http request completed	bc80b01a-9a8d-4a99-9cd0-ac1527ad3526	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/TokenUsageTrend.vue_vue_type_script_setup_true_lang-aqjoKx0Q.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "bc80b01a-9a8d-4a99-9cd0-ac1527ad3526", "status_code": 200, "completed_at": "2026-02-25T11:13:56.014524063+08:00", "client_request_id": ""}
364	2026-02-25 11:13:56.01484+08	info	http.access	http request completed	b09c620f-12ab-4280-b352-495599e40084	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/vendor-chart-BqAhThnj.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "b09c620f-12ab-4280-b352-495599e40084", "status_code": 200, "completed_at": "2026-02-25T11:13:56.014821862+08:00", "client_request_id": ""}
365	2026-02-25 11:13:56.047631+08	info	http.access	http request completed	8824a053-f45b-4bc0-82f9-6ab8ea14763a	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage/dashboard/models", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "8824a053-f45b-4bc0-82f9-6ab8ea14763a", "status_code": 200, "completed_at": "2026-02-25T11:13:56.047587383+08:00", "client_request_id": ""}
366	2026-02-25 11:13:56.04811+08	info	http.access	http request completed	7bc674a2-c243-4711-9a6e-a53b1f78389b	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "7bc674a2-c243-4711-9a6e-a53b1f78389b", "status_code": 200, "completed_at": "2026-02-25T11:13:56.04808588+08:00", "client_request_id": ""}
367	2026-02-25 11:13:56.04883+08	info	http.access	http request completed	bf087477-1451-4d13-ba0f-12aefe1f7611	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 4, "request_id": "bf087477-1451-4d13-ba0f-12aefe1f7611", "status_code": 200, "completed_at": "2026-02-25T11:13:56.048794976+08:00", "client_request_id": ""}
368	2026-02-25 11:13:56.051099+08	info	http.access	http request completed	a7a14b15-751f-4f2a-8a9f-8e9e29375332	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/announcements", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 7, "request_id": "a7a14b15-751f-4f2a-8a9f-8e9e29375332", "status_code": 200, "completed_at": "2026-02-25T11:13:56.051079664+08:00", "client_request_id": ""}
369	2026-02-25 11:13:56.051406+08	info	http.access	http request completed	7efe74d1-b0c7-4309-8d9d-c819c62ea138	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/KeysView-neHggVFv.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "7efe74d1-b0c7-4309-8d9d-c819c62ea138", "status_code": 200, "completed_at": "2026-02-25T11:13:56.051386662+08:00", "client_request_id": ""}
370	2026-02-25 11:13:56.05311+08	info	http.access	http request completed	07191c3e-487e-420d-8b17-7a2b1364d154	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/TablePageLayout-aLZmGbo3.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "07191c3e-487e-420d-8b17-7a2b1364d154", "status_code": 200, "completed_at": "2026-02-25T11:13:56.053096453+08:00", "client_request_id": ""}
371	2026-02-25 11:13:56.05315+08	info	http.access	http request completed	afb06a60-236d-4a36-9c61-ae99ac333c1e	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/keys-Bav_KspB.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "afb06a60-236d-4a36-9c61-ae99ac333c1e", "status_code": 200, "completed_at": "2026-02-25T11:13:56.053134252+08:00", "client_request_id": ""}
372	2026-02-25 11:13:56.053307+08	info	http.access	http request completed	ae803ba2-168d-496d-929e-12f33453f60f	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage/dashboard/trend", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 8, "request_id": "ae803ba2-168d-496d-929e-12f33453f60f", "status_code": 200, "completed_at": "2026-02-25T11:13:56.053293551+08:00", "client_request_id": ""}
373	2026-02-25 11:13:56.05389+08	info	http.access	http request completed	8748753f-83f1-4be1-8adf-708dbd88a04a	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/TablePageLayout-eKTo0RsV.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "8748753f-83f1-4be1-8adf-708dbd88a04a", "status_code": 200, "completed_at": "2026-02-25T11:13:56.053880848+08:00", "client_request_id": ""}
374	2026-02-25 11:13:56.055627+08	info	http.access	http request completed	b4707108-a4a2-4cf0-b386-a3bda513c127	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/Pagination-DtcDDVEA.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "b4707108-a4a2-4cf0-b386-a3bda513c127", "status_code": 200, "completed_at": "2026-02-25T11:13:56.055616139+08:00", "client_request_id": ""}
375	2026-02-25 11:13:56.055646+08	info	http.access	http request completed	f5bf72bd-af4e-4c55-9137-8ff7eda19564	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/DataTable-wk4w1kiu.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "f5bf72bd-af4e-4c55-9137-8ff7eda19564", "status_code": 200, "completed_at": "2026-02-25T11:13:56.055629839+08:00", "client_request_id": ""}
376	2026-02-25 11:13:56.064227+08	info	http.access	http request completed	7b0cb721-ebb8-49e1-b4fc-3bf8e6c0150d	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/DataTable-CMXPVGQy.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "7b0cb721-ebb8-49e1-b4fc-3bf8e6c0150d", "status_code": 200, "completed_at": "2026-02-25T11:13:56.064219192+08:00", "client_request_id": ""}
377	2026-02-25 11:13:56.064227+08	info	http.access	http request completed	7040443c-00ce-49b5-93a4-0e1644c9ce83	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/Pagination-FUaRDcBY.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "7040443c-00ce-49b5-93a4-0e1644c9ce83", "status_code": 200, "completed_at": "2026-02-25T11:13:56.064217092+08:00", "client_request_id": ""}
378	2026-02-25 11:13:56.064222+08	info	http.access	http request completed	03db70df-071f-4234-9e08-df4af32e860e	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/ConfirmDialog.vue_vue_type_script_setup_true_lang-Dlp3dUO2.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "03db70df-071f-4234-9e08-df4af32e860e", "status_code": 200, "completed_at": "2026-02-25T11:13:56.064210292+08:00", "client_request_id": ""}
379	2026-02-25 11:13:56.064482+08	info	http.access	http request completed	e3819de4-c9b6-4bb4-9633-d8017a96568a	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/GroupBadge.vue_vue_type_script_setup_true_lang-Cej1HtUK.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "e3819de4-c9b6-4bb4-9633-d8017a96568a", "status_code": 200, "completed_at": "2026-02-25T11:13:56.06447349+08:00", "client_request_id": ""}
380	2026-02-25 11:13:56.067723+08	info	http.access	http request completed	e041ea99-af3b-4b13-81e1-ebacea04f0b3	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/PlatformIcon.vue_vue_type_script_setup_true_lang-DDJ5Ol8Z.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "e041ea99-af3b-4b13-81e1-ebacea04f0b3", "status_code": 200, "completed_at": "2026-02-25T11:13:56.067710373+08:00", "client_request_id": ""}
381	2026-02-25 11:13:56.067895+08	info	http.access	http request completed	5f78363f-6449-4d7b-b17d-0e6687b279df	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/GroupOptionItem.vue_vue_type_script_setup_true_lang-DJgQlkUJ.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "5f78363f-6449-4d7b-b17d-0e6687b279df", "status_code": 200, "completed_at": "2026-02-25T11:13:56.067886872+08:00", "client_request_id": ""}
382	2026-02-25 11:13:56.067987+08	info	http.access	http request completed	95dab1b1-a030-468d-876a-b9172c437237	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/UsageView-CYHjTYYV.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "95dab1b1-a030-468d-876a-b9172c437237", "status_code": 200, "completed_at": "2026-02-25T11:13:56.067975471+08:00", "client_request_id": ""}
383	2026-02-25 11:13:56.075177+08	info	http.access	http request completed	9f74ee62-00bd-4b98-920b-7ae2cb5dc0f8	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage/dashboard/stats", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 7, "request_id": "9f74ee62-00bd-4b98-920b-7ae2cb5dc0f8", "status_code": 200, "completed_at": "2026-02-25T11:13:56.075146032+08:00", "client_request_id": ""}
384	2026-02-25 11:13:58.211027+08	info	http.access	http request completed	135d00a1-0620-4ae9-b021-4e1eab7d9bbf	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/settings/admin-api-key", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "135d00a1-0620-4ae9-b021-4e1eab7d9bbf", "status_code": 200, "completed_at": "2026-02-25T11:13:58.211001455+08:00", "client_request_id": ""}
385	2026-02-25 11:13:58.211027+08	info	http.access	http request completed	6c01321a-ada9-4c5a-b2ed-96e8b43b77fb	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/settings/stream-timeout", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "6c01321a-ada9-4c5a-b2ed-96e8b43b77fb", "status_code": 200, "completed_at": "2026-02-25T11:13:58.211010155+08:00", "client_request_id": ""}
386	2026-02-25 11:13:58.211717+08	info	http.access	http request completed	1e7fc900-6202-449c-95df-5daffcf9a44d	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/settings", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "1e7fc900-6202-449c-95df-5daffcf9a44d", "status_code": 200, "completed_at": "2026-02-25T11:13:58.211705452+08:00", "client_request_id": ""}
387	2026-02-25 11:13:58.215583+08	info	http.access	http request completed	946ebc30-34b6-44ce-918f-1e879c0683a3	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/announcements", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 7, "request_id": "946ebc30-34b6-44ce-918f-1e879c0683a3", "status_code": 200, "completed_at": "2026-02-25T11:13:58.21555613+08:00", "client_request_id": ""}
388	2026-02-25 11:14:02.217187+08	info	http.access	http request completed	2ac148cc-607e-416a-aefa-7e81797e5b4b	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/settings/ldap/test", "method": "POST", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 7, "request_id": "2ac148cc-607e-416a-aefa-7e81797e5b4b", "status_code": 200, "completed_at": "2026-02-25T11:14:02.21716681+08:00", "client_request_id": ""}
389	2026-02-25 11:14:04.824924+08	info	http.access	http request completed	d3610f50-c083-4be2-b67f-ae0298a7c598	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/settings/ldap/sync", "method": "POST", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 15, "request_id": "d3610f50-c083-4be2-b67f-ae0298a7c598", "status_code": 200, "completed_at": "2026-02-25T11:14:04.824884443+08:00", "client_request_id": ""}
390	2026-02-25 11:14:11.853541+08	info	http.access	http request completed	3024f9c0-f608-4393-a8b6-531cb6a25288	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/settings/ldap/test", "method": "POST", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 7, "request_id": "3024f9c0-f608-4393-a8b6-531cb6a25288", "status_code": 200, "completed_at": "2026-02-25T11:14:11.853523881+08:00", "client_request_id": ""}
391	2026-02-25 11:14:17.479829+08	info	http.access	http request completed	ab6f0982-7414-431c-8022-e4bec1d98366	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/settings/ldap/sync", "method": "POST", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 13, "request_id": "ab6f0982-7414-431c-8022-e4bec1d98366", "status_code": 200, "completed_at": "2026-02-25T11:14:17.479805567+08:00", "client_request_id": ""}
392	2026-02-25 11:14:22.884926+08	info	http.access	http request completed	f488af96-be99-4c6f-9a5c-8e3c894ca970	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/settings/ldap/sync", "method": "POST", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 15, "request_id": "f488af96-be99-4c6f-9a5c-8e3c894ca970", "status_code": 200, "completed_at": "2026-02-25T11:14:22.884895058+08:00", "client_request_id": ""}
393	2026-02-25 11:14:56.01155+08	info	http.access	http request completed	6e082be4-e0a1-45f7-8e9a-ab7e653ab793	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "6e082be4-e0a1-45f7-8e9a-ab7e653ab793", "status_code": 200, "completed_at": "2026-02-25T11:14:56.01153557+08:00", "client_request_id": ""}
394	2026-02-25 11:15:37.325561+08	info	http.access	http request completed	cc083f18-496f-4dc2-9291-7b30e53fa497	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/logout", "method": "POST", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "cc083f18-496f-4dc2-9291-7b30e53fa497", "status_code": 200, "completed_at": "2026-02-25T11:15:37.325543323+08:00", "client_request_id": ""}
395	2026-02-25 11:15:37.360593+08	info	http.access	http request completed	e40a993b-664a-401d-8c65-0fc445c1a348	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/settings/public", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "e40a993b-664a-401d-8c65-0fc445c1a348", "status_code": 200, "completed_at": "2026-02-25T11:15:37.360578127+08:00", "client_request_id": ""}
396	2026-02-25 11:15:46.914829+08	error	stdlog	[LDAP] user search failed identifier=wanghongping: error: code=*** reason="USER_NOT_FOUND" message="user not found" metadata=map[]	\N	\N	\N	\N	\N	\N	{"env": "production", "service": "sub2api", "legacy_stdlog": true}
397	2026-02-25 11:15:46.915023+08	info	http.access	http request completed	99bd6f07-3e45-4d12-a526-15a01a0254a7	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/login", "method": "POST", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 9, "request_id": "99bd6f07-3e45-4d12-a526-15a01a0254a7", "status_code": 401, "completed_at": "2026-02-25T11:15:46.915009314+08:00", "client_request_id": ""}
398	2026-02-25 11:16:49.341257+08	info	http.access	http request completed	bf61f37d-e739-44ee-a5d2-d3f18ca2b949	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/login", "method": "POST", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 51, "request_id": "bf61f37d-e739-44ee-a5d2-d3f18ca2b949", "status_code": 200, "completed_at": "2026-02-25T11:16:49.341239274+08:00", "client_request_id": ""}
399	2026-02-25 11:16:49.348349+08	info	http.access	http request completed	aee70a94-b1fd-47d6-a149-ece57367576c	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/subscriptions/active", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "aee70a94-b1fd-47d6-a149-ece57367576c", "status_code": 200, "completed_at": "2026-02-25T11:16:49.348324835+08:00", "client_request_id": ""}
400	2026-02-25 11:16:49.366792+08	info	http.access	http request completed	a8a7a408-b513-4469-ad8a-d50df9d1fc2d	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "a8a7a408-b513-4469-ad8a-d50df9d1fc2d", "status_code": 200, "completed_at": "2026-02-25T11:16:49.366736933+08:00", "client_request_id": ""}
401	2026-02-25 11:16:49.368062+08	info	http.access	http request completed	7263eb6d-c760-4ba5-b95c-07b28f97b412	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/announcements", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 5, "request_id": "7263eb6d-c760-4ba5-b95c-07b28f97b412", "status_code": 200, "completed_at": "2026-02-25T11:16:49.368032926+08:00", "client_request_id": ""}
402	2026-02-25 11:16:49.370831+08	info	http.access	http request completed	ee97ba92-1e15-4586-92cb-64833241d37a	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage/dashboard/trend", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "ee97ba92-1e15-4586-92cb-64833241d37a", "status_code": 200, "completed_at": "2026-02-25T11:16:49.370792311+08:00", "client_request_id": ""}
403	2026-02-25 11:16:49.370958+08	info	http.access	http request completed	5fa77848-5aef-40f0-8395-835ee915d699	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage/dashboard/models", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "5fa77848-5aef-40f0-8395-835ee915d699", "status_code": 200, "completed_at": "2026-02-25T11:16:49.37093851+08:00", "client_request_id": ""}
404	2026-02-25 11:16:49.372911+08	info	http.access	http request completed	83e1d654-fd08-4eb3-940f-3e800fe481df	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "83e1d654-fd08-4eb3-940f-3e800fe481df", "status_code": 200, "completed_at": "2026-02-25T11:16:49.372881299+08:00", "client_request_id": ""}
405	2026-02-25 11:16:49.379277+08	info	http.access	http request completed	623774da-66ca-4be8-a4e1-831bff43ded0	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage/dashboard/stats", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 5, "request_id": "623774da-66ca-4be8-a4e1-831bff43ded0", "status_code": 200, "completed_at": "2026-02-25T11:16:49.379258564+08:00", "client_request_id": ""}
406	2026-02-25 11:16:54.585134+08	info	http.access	http request completed	8c5501c5-8b7e-4637-8ef2-3b9de8d879a0	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/settings/admin-api-key", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "8c5501c5-8b7e-4637-8ef2-3b9de8d879a0", "status_code": 200, "completed_at": "2026-02-25T11:16:54.585090515+08:00", "client_request_id": ""}
407	2026-02-25 11:16:54.58534+08	info	http.access	http request completed	b30b058c-09aa-456d-888a-c2fa3bacd0b0	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/settings/stream-timeout", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "b30b058c-09aa-456d-888a-c2fa3bacd0b0", "status_code": 200, "completed_at": "2026-02-25T11:16:54.585319314+08:00", "client_request_id": ""}
408	2026-02-25 11:16:54.585758+08	info	http.access	http request completed	68beb03f-29a3-4fde-b025-0f97e9f6f8ec	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/settings", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "68beb03f-29a3-4fde-b025-0f97e9f6f8ec", "status_code": 200, "completed_at": "2026-02-25T11:16:54.585738211+08:00", "client_request_id": ""}
409	2026-02-25 11:16:54.588722+08	info	http.access	http request completed	446bbaf0-bd98-447e-a221-0ea0bb9274e8	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/announcements", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 5, "request_id": "446bbaf0-bd98-447e-a221-0ea0bb9274e8", "status_code": 200, "completed_at": "2026-02-25T11:16:54.588685195+08:00", "client_request_id": ""}
425	2026-02-25 11:18:12.034376+08	info	http.access	http request completed	817ae173-a05e-473d-a9b9-c7cd88f65bbe	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/login", "method": "POST", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 52, "request_id": "817ae173-a05e-473d-a9b9-c7cd88f65bbe", "status_code": 200, "completed_at": "2026-02-25T11:18:12.034352753+08:00", "client_request_id": ""}
426	2026-02-25 11:18:12.041843+08	info	http.access	http request completed	9a5d6bb5-0f15-45e6-969e-2b09cf559a88	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/subscriptions/active", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "9a5d6bb5-0f15-45e6-969e-2b09cf559a88", "status_code": 200, "completed_at": "2026-02-25T11:18:12.041809112+08:00", "client_request_id": ""}
427	2026-02-25 11:18:12.057577+08	info	http.access	http request completed	e6da1736-8b93-43c7-aefb-7b607c9bdb55	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/announcements", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 5, "request_id": "e6da1736-8b93-43c7-aefb-7b607c9bdb55", "status_code": 200, "completed_at": "2026-02-25T11:18:12.057548924+08:00", "client_request_id": ""}
428	2026-02-25 11:18:12.058189+08	info	http.access	http request completed	fe19c2a6-c853-4034-9a54-c6c2da77f456	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage/dashboard/trend", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "fe19c2a6-c853-4034-9a54-c6c2da77f456", "status_code": 200, "completed_at": "2026-02-25T11:18:12.05816272+08:00", "client_request_id": ""}
429	2026-02-25 11:18:12.058359+08	info	http.access	http request completed	96a3e4b7-2177-4bcf-b382-8ab10aa94049	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage/dashboard/models", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "96a3e4b7-2177-4bcf-b382-8ab10aa94049", "status_code": 200, "completed_at": "2026-02-25T11:18:12.058341219+08:00", "client_request_id": ""}
430	2026-02-25 11:18:12.058388+08	info	http.access	http request completed	34c28e01-a4a8-4a73-9353-d54fc26100f9	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "34c28e01-a4a8-4a73-9353-d54fc26100f9", "status_code": 200, "completed_at": "2026-02-25T11:18:12.058370719+08:00", "client_request_id": ""}
410	2026-02-25 11:16:59.402057+08	info	http.access	http request completed	45e77987-eb9b-4398-8a71-b2c25242765d	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/settings/ldap/test", "method": "POST", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 9, "request_id": "45e77987-eb9b-4398-8a71-b2c25242765d", "status_code": 200, "completed_at": "2026-02-25T11:16:59.402029591+08:00", "client_request_id": ""}
411	2026-02-25 11:17:40.54789+08	info	http.access	http request completed	45bc79af-b17b-48b3-932a-146ed17bacd9	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/settings", "method": "PUT", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 51, "request_id": "45bc79af-b17b-48b3-932a-146ed17bacd9", "status_code": 200, "completed_at": "2026-02-25T11:17:40.547876598+08:00", "client_request_id": ""}
412	2026-02-25 11:17:40.553084+08	info	http.access	http request completed	5dc0bf81-45ca-4b97-bd73-2962e53d6d12	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/settings/public", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "5dc0bf81-45ca-4b97-bd73-2962e53d6d12", "status_code": 200, "completed_at": "2026-02-25T11:17:40.553065769+08:00", "client_request_id": ""}
413	2026-02-25 11:17:45.215201+08	info	http.access	http request completed	ab8bfd95-c62a-4df7-a41d-7f2a1971174a	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/logout", "method": "POST", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "ab8bfd95-c62a-4df7-a41d-7f2a1971174a", "status_code": 200, "completed_at": "2026-02-25T11:17:45.215183837+08:00", "client_request_id": ""}
414	2026-02-25 11:17:45.236141+08	info	http.access	http request completed	02a346d0-3af9-43eb-9630-198eefa112cb	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/settings/public", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 1, "request_id": "02a346d0-3af9-43eb-9630-198eefa112cb", "status_code": 200, "completed_at": "2026-02-25T11:17:45.236114821+08:00", "client_request_id": ""}
415	2026-02-25 11:17:52.633551+08	info	http.access	http request completed	21b48950-4ab8-4930-a4d0-73010811739b	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/login", "method": "POST", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 80, "request_id": "21b48950-4ab8-4930-a4d0-73010811739b", "status_code": 200, "completed_at": "2026-02-25T11:17:52.63353475+08:00", "client_request_id": ""}
416	2026-02-25 11:17:52.641068+08	info	http.access	http request completed	a7dcfd6c-6488-4a3d-9154-97f37fd727e7	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/subscriptions/active", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "a7dcfd6c-6488-4a3d-9154-97f37fd727e7", "status_code": 200, "completed_at": "2026-02-25T11:17:52.641046508+08:00", "client_request_id": ""}
417	2026-02-25 11:17:52.67372+08	info	http.access	http request completed	e0a8d71b-c346-478e-bbd1-40250d246432	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/announcements", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 5, "request_id": "e0a8d71b-c346-478e-bbd1-40250d246432", "status_code": 200, "completed_at": "2026-02-25T11:17:52.673705226+08:00", "client_request_id": ""}
418	2026-02-25 11:17:52.675212+08	info	http.access	http request completed	5fbd28f2-c0c4-40e6-b3a2-8808b2d318db	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "5fbd28f2-c0c4-40e6-b3a2-8808b2d318db", "status_code": 200, "completed_at": "2026-02-25T11:17:52.675189018+08:00", "client_request_id": ""}
419	2026-02-25 11:17:52.675372+08	info	http.access	http request completed	1b53eeb9-037d-4d6b-87c5-586ea0d13749	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage/dashboard/models", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "1b53eeb9-037d-4d6b-87c5-586ea0d13749", "status_code": 200, "completed_at": "2026-02-25T11:17:52.675355917+08:00", "client_request_id": ""}
420	2026-02-25 11:17:52.675415+08	info	http.access	http request completed	8b0a7b45-abe4-4981-9001-6a14ac7860ee	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage/dashboard/trend", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "8b0a7b45-abe4-4981-9001-6a14ac7860ee", "status_code": 200, "completed_at": "2026-02-25T11:17:52.675402916+08:00", "client_request_id": ""}
421	2026-02-25 11:17:52.676242+08	info	http.access	http request completed	7d6cbbbe-f6c2-451f-aa2e-6e5e47b1b447	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "7d6cbbbe-f6c2-451f-aa2e-6e5e47b1b447", "status_code": 200, "completed_at": "2026-02-25T11:17:52.676223712+08:00", "client_request_id": ""}
422	2026-02-25 11:17:52.694748+08	info	http.access	http request completed	6bea51fe-7d4b-4799-9e16-ba66579cdfd4	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage/dashboard/stats", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 5, "request_id": "6bea51fe-7d4b-4799-9e16-ba66579cdfd4", "status_code": 200, "completed_at": "2026-02-25T11:17:52.694719909+08:00", "client_request_id": ""}
423	2026-02-25 11:18:08.214176+08	info	http.access	http request completed	6e5d5c45-af8a-43f8-bf94-f0637f406aa3	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/logout", "method": "POST", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "6e5d5c45-af8a-43f8-bf94-f0637f406aa3", "status_code": 200, "completed_at": "2026-02-25T11:18:08.214159508+08:00", "client_request_id": ""}
424	2026-02-25 11:18:08.234187+08	info	http.access	http request completed	fa6f234c-72b8-4551-84d3-cab432e8c7f9	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/settings/public", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 1, "request_id": "fa6f234c-72b8-4551-84d3-cab432e8c7f9", "status_code": 200, "completed_at": "2026-02-25T11:18:08.234154296+08:00", "client_request_id": ""}
433	2026-02-25 11:18:13.872984+08	info	http.access	http request completed	168bda94-98d9-4818-a042-6f020f6f1bcd	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/settings/stream-timeout", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "168bda94-98d9-4818-a042-6f020f6f1bcd", "status_code": 200, "completed_at": "2026-02-25T11:18:13.87296156+08:00", "client_request_id": ""}
431	2026-02-25 11:18:12.059055+08	info	http.access	http request completed	7faae2bd-aba5-4206-b6fe-aa26e5d6e815	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "7faae2bd-aba5-4206-b6fe-aa26e5d6e815", "status_code": 200, "completed_at": "2026-02-25T11:18:12.059019315+08:00", "client_request_id": ""}
432	2026-02-25 11:18:12.075821+08	info	http.access	http request completed	db025fd6-ead7-4e6e-b870-4e7eb72472b0	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage/dashboard/stats", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 5, "request_id": "db025fd6-ead7-4e6e-b870-4e7eb72472b0", "status_code": 200, "completed_at": "2026-02-25T11:18:12.075800221+08:00", "client_request_id": ""}
449	2026-02-25 11:19:33.077105+08	info	http.access	http request completed	2811cd26-7c75-4648-b702-80b0efd0eb0d	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage/stats", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "2811cd26-7c75-4648-b702-80b0efd0eb0d", "status_code": 200, "completed_at": "2026-02-25T11:19:33.077084127+08:00", "client_request_id": ""}
450	2026-02-25 11:19:33.077622+08	info	http.access	http request completed	cb8c4a67-08d7-4e07-a291-9b9c46210993	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "cb8c4a67-08d7-4e07-a291-9b9c46210993", "status_code": 200, "completed_at": "2026-02-25T11:19:33.077608324+08:00", "client_request_id": ""}
451	2026-02-25 11:19:33.077658+08	info	http.access	http request completed	54a3e11d-82e6-4886-b8f3-8158dff03457	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/keys", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "54a3e11d-82e6-4886-b8f3-8158dff03457", "status_code": 200, "completed_at": "2026-02-25T11:19:33.077648223+08:00", "client_request_id": ""}
452	2026-02-25 11:19:33.079068+08	info	http.access	http request completed	f238a24b-c94f-4fc9-9688-05891228ba6d	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/announcements", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 4, "request_id": "f238a24b-c94f-4fc9-9688-05891228ba6d", "status_code": 200, "completed_at": "2026-02-25T11:19:33.079046916+08:00", "client_request_id": ""}
453	2026-02-25 11:19:33.089669+08	info	http.access	http request completed	29ee4f07-05ad-47da-a6f3-ff93b0b1fa80	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/RedeemView-ChkGqhY_.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "29ee4f07-05ad-47da-a6f3-ff93b0b1fa80", "status_code": 200, "completed_at": "2026-02-25T11:19:33.089656656+08:00", "client_request_id": ""}
454	2026-02-25 11:19:33.089857+08	info	http.access	http request completed	388ac835-0371-4a20-a608-f43d27642400	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/RedeemView-CeViwvap.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "388ac835-0371-4a20-a608-f43d27642400", "status_code": 200, "completed_at": "2026-02-25T11:19:33.089846655+08:00", "client_request_id": ""}
455	2026-02-25 11:19:33.590313+08	info	http.access	http request completed	f4047b50-38d4-4b2e-9ab1-79a3486e3787	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/settings/public", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "f4047b50-38d4-4b2e-9ab1-79a3486e3787", "status_code": 200, "completed_at": "2026-02-25T11:19:33.590291856+08:00", "client_request_id": ""}
456	2026-02-25 11:19:33.592189+08	info	http.access	http request completed	8ca5632b-6395-4bb0-802f-8b13db175124	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/keys", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "8ca5632b-6395-4bb0-802f-8b13db175124", "status_code": 200, "completed_at": "2026-02-25T11:19:33.592167945+08:00", "client_request_id": ""}
457	2026-02-25 11:19:33.593644+08	info	http.access	http request completed	853735c0-1037-440c-ad52-2ba3cc554784	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/announcements", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 4, "request_id": "853735c0-1037-440c-ad52-2ba3cc554784", "status_code": 200, "completed_at": "2026-02-25T11:19:33.593612837+08:00", "client_request_id": ""}
458	2026-02-25 11:19:33.594702+08	info	http.access	http request completed	511868db-e305-4c5d-8b56-af13ef93d2c8	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/groups/rates", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 5, "request_id": "511868db-e305-4c5d-8b56-af13ef93d2c8", "status_code": 200, "completed_at": "2026-02-25T11:19:33.594677831+08:00", "client_request_id": ""}
459	2026-02-25 11:19:33.5969+08	info	http.access	http request completed	3f7d7a90-1548-4f48-ac18-986dc09faf8b	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/groups/available", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 7, "request_id": "3f7d7a90-1548-4f48-ac18-986dc09faf8b", "status_code": 200, "completed_at": "2026-02-25T11:19:33.596881419+08:00", "client_request_id": ""}
460	2026-02-25 11:19:33.986539+08	info	http.access	http request completed	97db1c81-5ae8-4e69-a5d0-e7390cac0033	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage/dashboard/models", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "97db1c81-5ae8-4e69-a5d0-e7390cac0033", "status_code": 200, "completed_at": "2026-02-25T11:19:33.98651254+08:00", "client_request_id": ""}
461	2026-02-25 11:19:33.986895+08	info	http.access	http request completed	de3d58c3-0fc3-4b2f-8229-4cb2605804d1	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage/dashboard/trend", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "de3d58c3-0fc3-4b2f-8229-4cb2605804d1", "status_code": 200, "completed_at": "2026-02-25T11:19:33.986878837+08:00", "client_request_id": ""}
462	2026-02-25 11:19:33.98717+08	info	http.access	http request completed	e0d96bb0-7b91-4a13-b81d-e299b0604b0d	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "e0d96bb0-7b91-4a13-b81d-e299b0604b0d", "status_code": 200, "completed_at": "2026-02-25T11:19:33.987155636+08:00", "client_request_id": ""}
434	2026-02-25 11:18:13.873056+08	info	http.access	http request completed	b4df644c-a129-4749-b48d-d34924c40435	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/settings", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "b4df644c-a129-4749-b48d-d34924c40435", "status_code": 200, "completed_at": "2026-02-25T11:18:13.873041159+08:00", "client_request_id": ""}
435	2026-02-25 11:18:13.873583+08	info	http.access	http request completed	3a0d02f9-48fb-484a-abd7-3d55c869e92d	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/settings/admin-api-key", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "3a0d02f9-48fb-484a-abd7-3d55c869e92d", "status_code": 200, "completed_at": "2026-02-25T11:18:13.873563956+08:00", "client_request_id": ""}
436	2026-02-25 11:18:13.875298+08	info	http.access	http request completed	ce904d2f-c5af-4206-837b-6e7a99f8de99	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/announcements", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 4, "request_id": "ce904d2f-c5af-4206-837b-6e7a99f8de99", "status_code": 200, "completed_at": "2026-02-25T11:18:13.875270347+08:00", "client_request_id": ""}
481	2026-02-25 11:22:32.094968+08	info	http.access	http request completed	3c7bae85-c6e9-4a80-aa85-143c49f1b275	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "3c7bae85-c6e9-4a80-aa85-143c49f1b275", "status_code": 200, "completed_at": "2026-02-25T11:22:32.094951776+08:00", "client_request_id": ""}
437	2026-02-25 11:18:18.760514+08	info	http.access	http request completed	b02a3c26-d91a-4954-95ed-fbcdf3916b85	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/settings/ldap/sync", "method": "POST", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 25, "request_id": "b02a3c26-d91a-4954-95ed-fbcdf3916b85", "status_code": 200, "completed_at": "2026-02-25T11:18:18.76049273+08:00", "client_request_id": ""}
438	2026-02-25 11:19:12.049387+08	info	http.access	http request completed	bab0f826-10a8-4ce8-9547-f946aaf2602a	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "bab0f826-10a8-4ce8-9547-f946aaf2602a", "status_code": 200, "completed_at": "2026-02-25T11:19:12.049372155+08:00", "client_request_id": ""}
439	2026-02-25 11:19:24.502154+08	info	http.access	http request completed	2a068b6c-d94e-4ea5-a1a4-e7b88a04ea15	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/logout", "method": "POST", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "2a068b6c-d94e-4ea5-a1a4-e7b88a04ea15", "status_code": 200, "completed_at": "2026-02-25T11:19:24.502137817+08:00", "client_request_id": ""}
440	2026-02-25 11:19:24.536005+08	info	http.access	http request completed	2db2466a-c2d9-4b69-aa1e-cd4e06e00f8b	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/settings/public", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 1, "request_id": "2db2466a-c2d9-4b69-aa1e-cd4e06e00f8b", "status_code": 200, "completed_at": "2026-02-25T11:19:24.535980728+08:00", "client_request_id": ""}
441	2026-02-25 11:19:31.476757+08	info	http.access	http request completed	ba75d25c-93c5-499f-b87b-eaf39ef28f0a	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/login", "method": "POST", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 28, "request_id": "ba75d25c-93c5-499f-b87b-eaf39ef28f0a", "status_code": 200, "completed_at": "2026-02-25T11:19:31.476742478+08:00", "client_request_id": ""}
442	2026-02-25 11:19:31.483436+08	info	http.access	http request completed	e6165b47-dfb9-4233-8408-363671e6b21b	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/subscriptions/active", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "e6165b47-dfb9-4233-8408-363671e6b21b", "status_code": 200, "completed_at": "2026-02-25T11:19:31.483406841+08:00", "client_request_id": ""}
443	2026-02-25 11:19:31.49776+08	info	http.access	http request completed	d6b49438-3a38-453c-bd06-89dcb237c2b2	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage/dashboard/trend", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "d6b49438-3a38-453c-bd06-89dcb237c2b2", "status_code": 200, "completed_at": "2026-02-25T11:19:31.497718961+08:00", "client_request_id": ""}
444	2026-02-25 11:19:31.498331+08	info	http.access	http request completed	b7c62853-a72c-493b-b478-ad05154544f3	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "b7c62853-a72c-493b-b478-ad05154544f3", "status_code": 200, "completed_at": "2026-02-25T11:19:31.498287758+08:00", "client_request_id": ""}
445	2026-02-25 11:19:31.498335+08	info	http.access	http request completed	70610dbf-6f78-4bda-8a46-3dc7d3204942	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "70610dbf-6f78-4bda-8a46-3dc7d3204942", "status_code": 200, "completed_at": "2026-02-25T11:19:31.498317058+08:00", "client_request_id": ""}
446	2026-02-25 11:19:31.498682+08	info	http.access	http request completed	b99eafc8-f450-4034-9700-2a6b75384e57	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage/dashboard/models", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "b99eafc8-f450-4034-9700-2a6b75384e57", "status_code": 200, "completed_at": "2026-02-25T11:19:31.498669156+08:00", "client_request_id": ""}
447	2026-02-25 11:19:31.500059+08	info	http.access	http request completed	72e73a1c-45bd-4e02-959d-df3cc468852f	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/announcements", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 5, "request_id": "72e73a1c-45bd-4e02-959d-df3cc468852f", "status_code": 200, "completed_at": "2026-02-25T11:19:31.500044148+08:00", "client_request_id": ""}
448	2026-02-25 11:19:31.509296+08	info	http.access	http request completed	ec3a3349-d3bc-47bd-ad73-2da99bd89fda	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage/dashboard/stats", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 5, "request_id": "ec3a3349-d3bc-47bd-ad73-2da99bd89fda", "status_code": 200, "completed_at": "2026-02-25T11:19:31.509272996+08:00", "client_request_id": ""}
479	2026-02-25 11:20:31.496382+08	info	http.access	http request completed	7cd7b826-1855-40ba-80a4-4722955decab	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "7cd7b826-1855-40ba-80a4-4722955decab", "status_code": 200, "completed_at": "2026-02-25T11:20:31.496368094+08:00", "client_request_id": ""}
482	2026-02-25 11:23:16.575663+08	error	service.pricing	[Pricing] Failed to compute local hash: open data/model_pricing.json: no such file or directory	\N	\N	\N	\N	\N	\N	{"env": "production", "service": "sub2api", "component": "service.pricing", "legacy_printf": true}
483	2026-02-25 11:23:17.200316+08	error	service.pricing	[Pricing] Failed to save file: open data/model_pricing.json: permission denied	\N	\N	\N	\N	\N	\N	{"env": "production", "service": "sub2api", "component": "service.pricing", "legacy_printf": true}
484	2026-02-25 11:23:17.203064+08	error	service.pricing	[Pricing] Failed to save hash: open data/model_pricing.sha256: permission denied	\N	\N	\N	\N	\N	\N	{"env": "production", "service": "sub2api", "component": "service.pricing", "legacy_printf": true}
485	2026-02-25 11:23:32.092589+08	info	http.access	http request completed	9415e55b-2c04-461e-b7c2-8ccaa4fbbc73	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "9415e55b-2c04-461e-b7c2-8ccaa4fbbc73", "status_code": 200, "completed_at": "2026-02-25T11:23:32.092575656+08:00", "client_request_id": ""}
463	2026-02-25 11:19:33.987313+08	info	http.access	http request completed	68e29146-a4d0-474a-ba45-b621ea78a33d	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 4, "request_id": "68e29146-a4d0-474a-ba45-b621ea78a33d", "status_code": 200, "completed_at": "2026-02-25T11:19:33.987305235+08:00", "client_request_id": ""}
464	2026-02-25 11:19:33.988549+08	info	http.access	http request completed	41e525ae-114d-4a5b-8e2a-123e7abf0280	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/announcements", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 5, "request_id": "41e525ae-114d-4a5b-8e2a-123e7abf0280", "status_code": 200, "completed_at": "2026-02-25T11:19:33.988525228+08:00", "client_request_id": ""}
465	2026-02-25 11:19:33.996388+08	info	http.access	http request completed	82251c73-1086-4682-bb09-d96a99b9bbf3	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage/dashboard/stats", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "82251c73-1086-4682-bb09-d96a99b9bbf3", "status_code": 200, "completed_at": "2026-02-25T11:19:33.996371584+08:00", "client_request_id": ""}
466	2026-02-25 11:19:34.565144+08	info	http.access	http request completed	75d5be06-7e51-4173-b4db-3f47de32f282	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/SubscriptionsView-DruRsOSy.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "75d5be06-7e51-4173-b4db-3f47de32f282", "status_code": 200, "completed_at": "2026-02-25T11:19:34.565131003+08:00", "client_request_id": ""}
467	2026-02-25 11:19:34.581647+08	info	http.access	http request completed	fd89f0b6-1aa9-48c4-bdde-37fe1fc353b4	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/subscriptions", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "fd89f0b6-1aa9-48c4-bdde-37fe1fc353b4", "status_code": 200, "completed_at": "2026-02-25T11:19:34.581632711+08:00", "client_request_id": ""}
468	2026-02-25 11:19:34.583719+08	info	http.access	http request completed	17865254-dc77-42a8-b821-85d03373f390	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/announcements", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 4, "request_id": "17865254-dc77-42a8-b821-85d03373f390", "status_code": 200, "completed_at": "2026-02-25T11:19:34.583680999+08:00", "client_request_id": ""}
469	2026-02-25 11:19:35.030227+08	info	http.access	http request completed	7a070269-c622-4801-87a3-f87369cf309f	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/settings/public", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "7a070269-c622-4801-87a3-f87369cf309f", "status_code": 200, "completed_at": "2026-02-25T11:19:35.030212501+08:00", "client_request_id": ""}
470	2026-02-25 11:19:35.034354+08	info	http.access	http request completed	765881c6-f148-421e-a4a5-dcf94893c432	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/announcements", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 4, "request_id": "765881c6-f148-421e-a4a5-dcf94893c432", "status_code": 200, "completed_at": "2026-02-25T11:19:35.034331578+08:00", "client_request_id": ""}
471	2026-02-25 11:19:35.04021+08	info	http.access	http request completed	50a552ac-77a6-47f7-a0a4-d2c442b43fd9	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/ProfileView-cUTA_I8J.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "50a552ac-77a6-47f7-a0a4-d2c442b43fd9", "status_code": 200, "completed_at": "2026-02-25T11:19:35.040184246+08:00", "client_request_id": ""}
472	2026-02-25 11:19:35.040385+08	info	http.access	http request completed	8470edba-785e-46e6-9763-1bf6b455114c	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/redeem/history", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 10, "request_id": "8470edba-785e-46e6-9763-1bf6b455114c", "status_code": 200, "completed_at": "2026-02-25T11:19:35.040362745+08:00", "client_request_id": ""}
473	2026-02-25 11:19:42.780287+08	info	http.access	http request completed	ab60e240-a299-4784-939e-34fd91bced5b	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage/dashboard/models", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "ab60e240-a299-4784-939e-34fd91bced5b", "status_code": 200, "completed_at": "2026-02-25T11:19:42.780268423+08:00", "client_request_id": ""}
474	2026-02-25 11:19:42.780287+08	info	http.access	http request completed	8e86755e-c2c6-4fba-a3be-057a9817bb81	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage/dashboard/trend", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "8e86755e-c2c6-4fba-a3be-057a9817bb81", "status_code": 200, "completed_at": "2026-02-25T11:19:42.780270323+08:00", "client_request_id": ""}
475	2026-02-25 11:19:42.780436+08	info	http.access	http request completed	169a056b-37a7-4c5f-87da-a4ea8a706e4a	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "169a056b-37a7-4c5f-87da-a4ea8a706e4a", "status_code": 200, "completed_at": "2026-02-25T11:19:42.780429622+08:00", "client_request_id": ""}
476	2026-02-25 11:19:42.780792+08	info	http.access	http request completed	8b854ad2-c407-47b6-9544-acdf4c0062b4	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "8b854ad2-c407-47b6-9544-acdf4c0062b4", "status_code": 200, "completed_at": "2026-02-25T11:19:42.78077152+08:00", "client_request_id": ""}
477	2026-02-25 11:19:42.781237+08	info	http.access	http request completed	9d4152b1-ed6e-4094-a867-61b0beb37ea4	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/announcements", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 5, "request_id": "9d4152b1-ed6e-4094-a867-61b0beb37ea4", "status_code": 200, "completed_at": "2026-02-25T11:19:42.781226417+08:00", "client_request_id": ""}
478	2026-02-25 11:19:42.790485+08	info	http.access	http request completed	baf2d6e9-658a-4503-bba5-fcdd8835eb73	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage/dashboard/stats", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 4, "request_id": "baf2d6e9-658a-4503-bba5-fcdd8835eb73", "status_code": 200, "completed_at": "2026-02-25T11:19:42.790470865+08:00", "client_request_id": ""}
480	2026-02-25 11:21:31.492963+08	info	http.access	http request completed	85813c29-98de-438a-bbc0-cfc2ab454e5c	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "85813c29-98de-438a-bbc0-cfc2ab454e5c", "status_code": 200, "completed_at": "2026-02-25T11:21:31.49294896+08:00", "client_request_id": ""}
486	2026-02-25 11:24:32.103184+08	info	http.access	http request completed	b3a7ebf7-746e-45cb-b40d-4e7ab8f2732d	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "b3a7ebf7-746e-45cb-b40d-4e7ab8f2732d", "status_code": 200, "completed_at": "2026-02-25T11:24:32.103171179+08:00", "client_request_id": ""}
487	2026-02-25 11:24:32.103988+08	info	http.access	http request completed	b82bdbb4-9dee-4669-a9b2-1761ef3951d6	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/subscriptions/active", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "b82bdbb4-9dee-4669-a9b2-1761ef3951d6", "status_code": 200, "completed_at": "2026-02-25T11:24:32.103977674+08:00", "client_request_id": ""}
488	2026-02-25 11:25:32.096974+08	info	http.access	http request completed	00a2149e-d740-42cd-a30c-6c2af2bd1389	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "00a2149e-d740-42cd-a30c-6c2af2bd1389", "status_code": 200, "completed_at": "2026-02-25T11:25:32.09695744+08:00", "client_request_id": ""}
489	2026-02-25 11:26:31.483803+08	info	http.access	http request completed	331789dd-3795-42b6-8ff4-c9f96d55e983	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "331789dd-3795-42b6-8ff4-c9f96d55e983", "status_code": 200, "completed_at": "2026-02-25T11:26:31.483786977+08:00", "client_request_id": ""}
490	2026-02-25 11:27:31.48412+08	info	http.access	http request completed	3356e73d-147f-4593-be89-31478e6be38e	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "3356e73d-147f-4593-be89-31478e6be38e", "status_code": 200, "completed_at": "2026-02-25T11:27:31.484104586+08:00", "client_request_id": ""}
491	2026-02-25 11:33:16.575485+08	error	service.pricing	[Pricing] Failed to compute local hash: open data/model_pricing.json: no such file or directory	\N	\N	\N	\N	\N	\N	{"env": "production", "service": "sub2api", "component": "service.pricing", "legacy_printf": true}
492	2026-02-25 11:33:17.821435+08	error	service.pricing	[Pricing] Failed to save file: open data/model_pricing.json: permission denied	\N	\N	\N	\N	\N	\N	{"env": "production", "service": "sub2api", "component": "service.pricing", "legacy_printf": true}
493	2026-02-25 11:33:17.824188+08	error	service.pricing	[Pricing] Failed to save hash: open data/model_pricing.sha256: permission denied	\N	\N	\N	\N	\N	\N	{"env": "production", "service": "sub2api", "component": "service.pricing", "legacy_printf": true}
494	2026-02-25 11:43:16.57614+08	error	service.pricing	[Pricing] Failed to compute local hash: open data/model_pricing.json: no such file or directory	\N	\N	\N	\N	\N	\N	{"env": "production", "service": "sub2api", "component": "service.pricing", "legacy_printf": true}
495	2026-02-25 11:43:17.436149+08	error	service.pricing	[Pricing] Failed to save file: open data/model_pricing.json: permission denied	\N	\N	\N	\N	\N	\N	{"env": "production", "service": "sub2api", "component": "service.pricing", "legacy_printf": true}
496	2026-02-25 11:43:17.438905+08	error	service.pricing	[Pricing] Failed to save hash: open data/model_pricing.sha256: permission denied	\N	\N	\N	\N	\N	\N	{"env": "production", "service": "sub2api", "component": "service.pricing", "legacy_printf": true}
497	2026-02-25 11:49:13.75327+08	info	http.access	http request completed	63805c0d-a454-47a3-b216-bb66ba5b2bc6	\N	\N	\N	\N	\N	{"env": "production", "path": "/", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 1, "request_id": "63805c0d-a454-47a3-b216-bb66ba5b2bc6", "status_code": 200, "completed_at": "2026-02-25T11:49:13.753238652+08:00", "client_request_id": ""}
498	2026-02-25 11:49:13.773025+08	info	http.access	http request completed	04132379-1787-49c6-9548-7ff226a7c2dd	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/index-CkKnxzIb.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "04132379-1787-49c6-9548-7ff226a7c2dd", "status_code": 200, "completed_at": "2026-02-25T11:49:13.77300683+08:00", "client_request_id": ""}
499	2026-02-25 11:49:13.773908+08	info	http.access	http request completed	e9ce73b9-d5ca-4fe1-ab04-410e60f82068	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/vendor-vue-4WNFgugS.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "e9ce73b9-d5ca-4fe1-ab04-410e60f82068", "status_code": 200, "completed_at": "2026-02-25T11:49:13.773884524+08:00", "client_request_id": ""}
500	2026-02-25 11:49:13.774262+08	info	http.access	http request completed	967d531b-5831-4ceb-99db-803f9b3d98a6	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/vendor-misc-DB0Q8XAf.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "967d531b-5831-4ceb-99db-803f9b3d98a6", "status_code": 200, "completed_at": "2026-02-25T11:49:13.774246022+08:00", "client_request_id": ""}
501	2026-02-25 11:49:13.775484+08	info	http.access	http request completed	3174afd0-5346-4090-89a1-afe6197b2fec	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/index-Dji9Snxu.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "3174afd0-5346-4090-89a1-afe6197b2fec", "status_code": 200, "completed_at": "2026-02-25T11:49:13.775456114+08:00", "client_request_id": ""}
502	2026-02-25 11:49:13.77597+08	info	http.access	http request completed	4339dbf7-f19a-4b12-abaf-50294f93da7c	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/vendor-misc-NmuJm1mp.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "4339dbf7-f19a-4b12-abaf-50294f93da7c", "status_code": 200, "completed_at": "2026-02-25T11:49:13.775950611+08:00", "client_request_id": ""}
503	2026-02-25 11:49:13.776699+08	info	http.access	http request completed	b0cb13a3-ec4a-4080-84ab-71a5fa636494	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/vendor-i18n-CF5oKjnm.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "b0cb13a3-ec4a-4080-84ab-71a5fa636494", "status_code": 200, "completed_at": "2026-02-25T11:49:13.776685207+08:00", "client_request_id": ""}
504	2026-02-25 11:49:13.833371+08	info	http.access	http request completed	f3a92b76-b7ca-4ab9-bb44-53aaab9feb3c	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/zh-joyDK6VH.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "f3a92b76-b7ca-4ab9-bb44-53aaab9feb3c", "status_code": 200, "completed_at": "2026-02-25T11:49:13.833344555+08:00", "client_request_id": ""}
505	2026-02-25 11:49:13.851373+08	info	http.access	http request completed	2e4a6989-b663-4e53-99d1-731dd4997ff1	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/HomeView-BEc80kvG.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "2e4a6989-b663-4e53-99d1-731dd4997ff1", "status_code": 200, "completed_at": "2026-02-25T11:49:13.851357843+08:00", "client_request_id": ""}
506	2026-02-25 11:49:13.851506+08	info	http.access	http request completed	718ce71e-e50a-46f7-8954-21e86472d005	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/LocaleSwitcher-BaVz3FTM.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "718ce71e-e50a-46f7-8954-21e86472d005", "status_code": 200, "completed_at": "2026-02-25T11:49:13.851495942+08:00", "client_request_id": ""}
507	2026-02-25 11:49:13.85158+08	info	http.access	http request completed	f96762e4-93c9-470e-9d31-966aa024e4d9	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/LocaleSwitcher-CjvPxOhx.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "f96762e4-93c9-470e-9d31-966aa024e4d9", "status_code": 200, "completed_at": "2026-02-25T11:49:13.851564442+08:00", "client_request_id": ""}
508	2026-02-25 11:49:13.851732+08	info	http.access	http request completed	f0bfe352-259e-48ba-b6bf-4c49300598c3	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/HomeView-Dww6Lv6Y.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "f0bfe352-259e-48ba-b6bf-4c49300598c3", "status_code": 200, "completed_at": "2026-02-25T11:49:13.851719141+08:00", "client_request_id": ""}
509	2026-02-25 11:49:13.856931+08	info	http.access	http request completed	da58ec59-22eb-467a-913b-f42731cd7b34	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 5, "request_id": "da58ec59-22eb-467a-913b-f42731cd7b34", "status_code": 200, "completed_at": "2026-02-25T11:49:13.856905009+08:00", "client_request_id": ""}
510	2026-02-25 11:49:13.925175+08	info	http.access	http request completed	7e2060cb-97cd-4e67-9547-4851126f4a67	\N	\N	\N	\N	\N	{"env": "production", "path": "/logo.png", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "7e2060cb-97cd-4e67-9547-4851126f4a67", "status_code": 200, "completed_at": "2026-02-25T11:49:13.925135085+08:00", "client_request_id": ""}
511	2026-02-25 11:49:13.928617+08	info	http.access	http request completed	96c0319c-fb88-4f5e-a39a-29d50ba86058	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/subscriptions/active", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "96c0319c-fb88-4f5e-a39a-29d50ba86058", "status_code": 200, "completed_at": "2026-02-25T11:49:13.928594064+08:00", "client_request_id": ""}
512	2026-02-25 11:49:13.930049+08	info	http.access	http request completed	6d6c3cea-62be-4b34-8f2a-1965e2843bdc	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 4, "request_id": "6d6c3cea-62be-4b34-8f2a-1965e2843bdc", "status_code": 200, "completed_at": "2026-02-25T11:49:13.930029455+08:00", "client_request_id": ""}
513	2026-02-25 11:49:15.811713+08	info	http.access	http request completed	b9f68479-6a16-45cd-9a67-c909924bda48	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/usage-DjeCvF1i.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "b9f68479-6a16-45cd-9a67-c909924bda48", "status_code": 200, "completed_at": "2026-02-25T11:49:15.811611675+08:00", "client_request_id": ""}
514	2026-02-25 11:49:15.811845+08	info	http.access	http request completed	b7fb4f4b-ec7f-4319-a5d2-d343ed406d20	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/DashboardView-DpyOZDdn.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "b7fb4f4b-ec7f-4319-a5d2-d343ed406d20", "status_code": 200, "completed_at": "2026-02-25T11:49:15.811822373+08:00", "client_request_id": ""}
515	2026-02-25 11:49:15.811815+08	info	http.access	http request completed	acfc6c18-d5c5-4811-9a6b-c355fb534033	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/LoadingSpinner-DI27EpD8.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "acfc6c18-d5c5-4811-9a6b-c355fb534033", "status_code": 200, "completed_at": "2026-02-25T11:49:15.811805473+08:00", "client_request_id": ""}
516	2026-02-25 11:49:15.811905+08	info	http.access	http request completed	bd2061b4-1d2b-4b11-9b5a-0748d637cdce	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/LoadingSpinner-DT-rtrW_.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "bd2061b4-1d2b-4b11-9b5a-0748d637cdce", "status_code": 200, "completed_at": "2026-02-25T11:49:15.811894073+08:00", "client_request_id": ""}
517	2026-02-25 11:49:15.811928+08	info	http.access	http request completed	7403a9a0-bd71-4fff-b205-da51bbc778f8	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/AppHeader-NeOcFzPI.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "7403a9a0-bd71-4fff-b205-da51bbc778f8", "status_code": 200, "completed_at": "2026-02-25T11:49:15.811913873+08:00", "client_request_id": ""}
518	2026-02-25 11:49:15.812055+08	info	http.access	http request completed	4673f166-d59f-430f-92cd-c4d907a35d03	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/AppLayout.vue_vue_type_script_setup_true_lang-CbvznAXW.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "4673f166-d59f-430f-92cd-c4d907a35d03", "status_code": 200, "completed_at": "2026-02-25T11:49:15.812041772+08:00", "client_request_id": ""}
519	2026-02-25 11:49:15.821509+08	info	http.access	http request completed	b1fc552f-f887-4aca-b2fb-bd5a7cdc8ee6	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/Select-7fPaeC0I.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "b1fc552f-f887-4aca-b2fb-bd5a7cdc8ee6", "status_code": 200, "completed_at": "2026-02-25T11:49:15.821497413+08:00", "client_request_id": ""}
520	2026-02-25 11:49:15.821516+08	info	http.access	http request completed	de4eb7bb-99af-4775-8044-4afb3ceaa7cc	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/DateRangePicker-CFGGkPM1.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "de4eb7bb-99af-4775-8044-4afb3ceaa7cc", "status_code": 200, "completed_at": "2026-02-25T11:49:15.821500313+08:00", "client_request_id": ""}
521	2026-02-25 11:49:15.821727+08	info	http.access	http request completed	4b07b672-53f5-489f-a018-25ee22f25784	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/Select-C5iZj_mq.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "4b07b672-53f5-489f-a018-25ee22f25784", "status_code": 200, "completed_at": "2026-02-25T11:49:15.821719312+08:00", "client_request_id": ""}
522	2026-02-25 11:49:15.82175+08	info	http.access	http request completed	3d48ed04-1d7c-44ee-94da-0fd119d9a6e9	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/DateRangePicker-WAZB4rcB.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "3d48ed04-1d7c-44ee-94da-0fd119d9a6e9", "status_code": 200, "completed_at": "2026-02-25T11:49:15.821707812+08:00", "client_request_id": ""}
523	2026-02-25 11:49:15.824594+08	info	http.access	http request completed	c39d3336-6d2b-4848-b7c5-821ee55c3af8	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/TokenUsageTrend.vue_vue_type_script_setup_true_lang-aqjoKx0Q.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "c39d3336-6d2b-4848-b7c5-821ee55c3af8", "status_code": 200, "completed_at": "2026-02-25T11:49:15.824581694+08:00", "client_request_id": ""}
524	2026-02-25 11:49:15.82521+08	info	http.access	http request completed	4a07c0ba-4247-4b70-8ef2-63ad5f732ff0	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/vendor-chart-BqAhThnj.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "4a07c0ba-4247-4b70-8ef2-63ad5f732ff0", "status_code": 200, "completed_at": "2026-02-25T11:49:15.82518029+08:00", "client_request_id": ""}
525	2026-02-25 11:49:15.827279+08	info	http.access	http request completed	c1836960-92ea-4fa3-92cb-88da7e044323	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/EmptyState.vue_vue_type_script_setup_true_lang-BCx0NwKs.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "c1836960-92ea-4fa3-92cb-88da7e044323", "status_code": 200, "completed_at": "2026-02-25T11:49:15.827255177+08:00", "client_request_id": ""}
526	2026-02-25 11:49:15.858625+08	info	http.access	http request completed	7dc6f883-7649-448e-8488-c1ff1b998a7d	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "7dc6f883-7649-448e-8488-c1ff1b998a7d", "status_code": 200, "completed_at": "2026-02-25T11:49:15.858587183+08:00", "client_request_id": ""}
527	2026-02-25 11:49:15.860707+08	info	http.access	http request completed	958db05d-5435-49ee-8ec2-51a0f98acc47	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 4, "request_id": "958db05d-5435-49ee-8ec2-51a0f98acc47", "status_code": 200, "completed_at": "2026-02-25T11:49:15.86067047+08:00", "client_request_id": ""}
528	2026-02-25 11:49:15.860777+08	info	http.access	http request completed	610543b4-bbf5-464c-8451-e6ee3fc8d9f7	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage/dashboard/models", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 5, "request_id": "610543b4-bbf5-464c-8451-e6ee3fc8d9f7", "status_code": 200, "completed_at": "2026-02-25T11:49:15.860760869+08:00", "client_request_id": ""}
529	2026-02-25 11:49:15.875391+08	info	http.access	http request completed	5aeecd13-47dc-4cf0-a149-856850fa9236	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/announcements", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 20, "request_id": "5aeecd13-47dc-4cf0-a149-856850fa9236", "status_code": 200, "completed_at": "2026-02-25T11:49:15.875348079+08:00", "client_request_id": ""}
530	2026-02-25 11:49:15.876469+08	info	http.access	http request completed	b00e8cb5-2ab1-43ac-8473-a86793e165d8	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage/dashboard/trend", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 20, "request_id": "b00e8cb5-2ab1-43ac-8473-a86793e165d8", "status_code": 200, "completed_at": "2026-02-25T11:49:15.876417172+08:00", "client_request_id": ""}
531	2026-02-25 11:49:15.877875+08	info	http.access	http request completed	b968524b-bc96-4775-9a0a-7fc574bd7b4d	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/KeysView-neHggVFv.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "b968524b-bc96-4775-9a0a-7fc574bd7b4d", "status_code": 200, "completed_at": "2026-02-25T11:49:15.877857463+08:00", "client_request_id": ""}
532	2026-02-25 11:49:15.879547+08	info	http.access	http request completed	09ea4af1-f527-4f71-a45b-1077a37bfd17	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage/dashboard/stats", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 8, "request_id": "09ea4af1-f527-4f71-a45b-1077a37bfd17", "status_code": 200, "completed_at": "2026-02-25T11:49:15.879521253+08:00", "client_request_id": ""}
533	2026-02-25 11:49:15.8868+08	info	http.access	http request completed	a26f7583-e1fe-4bf1-82a3-4450968d2660	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/TablePageLayout-eKTo0RsV.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "a26f7583-e1fe-4bf1-82a3-4450968d2660", "status_code": 200, "completed_at": "2026-02-25T11:49:15.886789108+08:00", "client_request_id": ""}
534	2026-02-25 11:49:15.886885+08	info	http.access	http request completed	08296e88-06c5-4ab6-b93b-1ffebba63b61	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/useClipboard-DfSApw15.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "08296e88-06c5-4ab6-b93b-1ffebba63b61", "status_code": 200, "completed_at": "2026-02-25T11:49:15.886875707+08:00", "client_request_id": ""}
535	2026-02-25 11:49:15.886913+08	info	http.access	http request completed	aeb9c859-6419-4973-960c-d972e34b3b18	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/keys-Bav_KspB.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "aeb9c859-6419-4973-960c-d972e34b3b18", "status_code": 200, "completed_at": "2026-02-25T11:49:15.886906907+08:00", "client_request_id": ""}
536	2026-02-25 11:49:15.887068+08	info	http.access	http request completed	5476c052-5c70-40d0-8e38-59ceba0bd359	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/TablePageLayout-aLZmGbo3.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "5476c052-5c70-40d0-8e38-59ceba0bd359", "status_code": 200, "completed_at": "2026-02-25T11:49:15.887051906+08:00", "client_request_id": ""}
537	2026-02-25 11:49:15.887491+08	info	http.access	http request completed	5cf19675-61a0-41d2-b5de-4558df8662d1	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/DataTable-wk4w1kiu.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "5cf19675-61a0-41d2-b5de-4558df8662d1", "status_code": 200, "completed_at": "2026-02-25T11:49:15.887480404+08:00", "client_request_id": ""}
538	2026-02-25 11:49:15.889797+08	info	http.access	http request completed	2fb49810-6998-497d-a1d2-413b763e10ae	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/Pagination-DtcDDVEA.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "2fb49810-6998-497d-a1d2-413b763e10ae", "status_code": 200, "completed_at": "2026-02-25T11:49:15.889783289+08:00", "client_request_id": ""}
539	2026-02-25 11:49:15.891307+08	info	http.access	http request completed	11e724d4-7307-4d3f-82e4-d13fec2c8fe6	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/Pagination-FUaRDcBY.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "11e724d4-7307-4d3f-82e4-d13fec2c8fe6", "status_code": 200, "completed_at": "2026-02-25T11:49:15.89129458+08:00", "client_request_id": ""}
540	2026-02-25 11:49:15.89135+08	info	http.access	http request completed	5b47cd4f-a3d1-4b52-a1eb-4c0793ee9714	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/DataTable-CMXPVGQy.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "5b47cd4f-a3d1-4b52-a1eb-4c0793ee9714", "status_code": 200, "completed_at": "2026-02-25T11:49:15.89133938+08:00", "client_request_id": ""}
541	2026-02-25 11:49:15.891326+08	info	http.access	http request completed	b5cdbb0b-4100-41a7-b66d-84eafcece174	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/ConfirmDialog.vue_vue_type_script_setup_true_lang-Dlp3dUO2.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "b5cdbb0b-4100-41a7-b66d-84eafcece174", "status_code": 200, "completed_at": "2026-02-25T11:49:15.89130888+08:00", "client_request_id": ""}
542	2026-02-25 11:49:15.891901+08	info	http.access	http request completed	2041d28d-89bb-4178-b2dc-cb2e5c04df55	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/GroupBadge.vue_vue_type_script_setup_true_lang-Cej1HtUK.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "2041d28d-89bb-4178-b2dc-cb2e5c04df55", "status_code": 200, "completed_at": "2026-02-25T11:49:15.891881376+08:00", "client_request_id": ""}
543	2026-02-25 11:49:15.892009+08	info	http.access	http request completed	22907d56-cdd3-4963-9b9b-fdee2e4dec54	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/PlatformIcon.vue_vue_type_script_setup_true_lang-DDJ5Ol8Z.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "22907d56-cdd3-4963-9b9b-fdee2e4dec54", "status_code": 200, "completed_at": "2026-02-25T11:49:15.891980676+08:00", "client_request_id": ""}
544	2026-02-25 11:49:15.893952+08	info	http.access	http request completed	16dc08c1-bef7-4275-92db-1f91da672c6d	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/GroupOptionItem.vue_vue_type_script_setup_true_lang-DJgQlkUJ.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "16dc08c1-bef7-4275-92db-1f91da672c6d", "status_code": 200, "completed_at": "2026-02-25T11:49:15.893940863+08:00", "client_request_id": ""}
545	2026-02-25 11:49:15.896052+08	info	http.access	http request completed	96ff6fdb-38de-4e4a-bac0-03193f2e0794	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/UsageView-CYHjTYYV.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "96ff6fdb-38de-4e4a-bac0-03193f2e0794", "status_code": 200, "completed_at": "2026-02-25T11:49:15.89602765+08:00", "client_request_id": ""}
546	2026-02-25 11:50:13.888597+08	info	http.access	http request completed	148f5305-ffc6-4a46-8700-afdd64ef9174	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 5, "request_id": "148f5305-ffc6-4a46-8700-afdd64ef9174", "status_code": 200, "completed_at": "2026-02-25T11:50:13.888556891+08:00", "client_request_id": ""}
547	2026-02-25 11:51:13.87939+08	info	http.access	http request completed	93743e8a-df20-47fb-b065-257a3c790778	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 5, "request_id": "93743e8a-df20-47fb-b065-257a3c790778", "status_code": 200, "completed_at": "2026-02-25T11:51:13.879362369+08:00", "client_request_id": ""}
548	2026-02-25 11:51:39.691647+08	warn	stdlog	Warning: server.trusted_proxies is empty in release mode; client IP trust chain is disabled	\N	\N	\N	\N	\N	\N	{"env": "production", "service": "sub2api", "legacy_stdlog": true}
549	2026-02-25 11:51:39.691672+08	warn	stdlog	Warning: CORS allowed_origins not configured; cross-origin requests will be rejected.	\N	\N	\N	\N	\N	\N	{"env": "production", "service": "sub2api", "legacy_stdlog": true}
550	2026-02-25 11:52:13.804551+08	info	http.access	http request completed	f886bc44-ba51-475e-a332-7288e27048c1	\N	\N	\N	\N	\N	{"env": "production", "path": "/dashboard", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 1, "request_id": "f886bc44-ba51-475e-a332-7288e27048c1", "status_code": 200, "completed_at": "2026-02-25T11:52:13.804530802+08:00", "client_request_id": ""}
551	2026-02-25 11:52:13.830477+08	info	http.access	http request completed	af90824f-c5c3-4267-b436-469b3b141504	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/index-CkKnxzIb.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "af90824f-c5c3-4267-b436-469b3b141504", "status_code": 200, "completed_at": "2026-02-25T11:52:13.830444749+08:00", "client_request_id": ""}
552	2026-02-25 11:52:13.830675+08	info	http.access	http request completed	2062dd46-c269-414b-b392-2f5bf91d4c5f	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/vendor-vue-4WNFgugS.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "2062dd46-c269-414b-b392-2f5bf91d4c5f", "status_code": 200, "completed_at": "2026-02-25T11:52:13.830656647+08:00", "client_request_id": ""}
553	2026-02-25 11:52:13.833342+08	info	http.access	http request completed	e2188702-d058-4f57-92b6-071b30a8638e	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/vendor-misc-DB0Q8XAf.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "e2188702-d058-4f57-92b6-071b30a8638e", "status_code": 200, "completed_at": "2026-02-25T11:52:13.833313832+08:00", "client_request_id": ""}
554	2026-02-25 11:52:13.834422+08	info	http.access	http request completed	59198aee-fafc-43ae-8a2b-1886f56eb436	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/index-Dji9Snxu.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "59198aee-fafc-43ae-8a2b-1886f56eb436", "status_code": 200, "completed_at": "2026-02-25T11:52:13.834388725+08:00", "client_request_id": ""}
555	2026-02-25 11:52:13.835692+08	info	http.access	http request completed	ffaab2c4-a97a-45b9-b8c9-7eec521169a0	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/vendor-misc-NmuJm1mp.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "ffaab2c4-a97a-45b9-b8c9-7eec521169a0", "status_code": 200, "completed_at": "2026-02-25T11:52:13.835626418+08:00", "client_request_id": ""}
556	2026-02-25 11:52:13.836366+08	info	http.access	http request completed	b5a0840c-f339-459e-9643-df29f64fcb61	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/vendor-i18n-CF5oKjnm.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "b5a0840c-f339-459e-9643-df29f64fcb61", "status_code": 200, "completed_at": "2026-02-25T11:52:13.836346014+08:00", "client_request_id": ""}
557	2026-02-25 11:52:13.879785+08	info	http.access	http request completed	5037c74c-6276-42f3-8d85-3fed60af41ab	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/zh-joyDK6VH.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "5037c74c-6276-42f3-8d85-3fed60af41ab", "status_code": 200, "completed_at": "2026-02-25T11:52:13.879728156+08:00", "client_request_id": ""}
558	2026-02-25 11:52:13.886632+08	info	http.access	http request completed	a281629c-ad3a-45d1-9eeb-2f7e6551cbcc	\N	\N	\N	\N	\N	{"env": "production", "path": "/logo.png", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "a281629c-ad3a-45d1-9eeb-2f7e6551cbcc", "status_code": 200, "completed_at": "2026-02-25T11:52:13.886607415+08:00", "client_request_id": ""}
559	2026-02-25 11:52:13.895492+08	info	http.access	http request completed	68446a50-d149-46ca-b952-3cdbb312cd57	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/usage-DjeCvF1i.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "68446a50-d149-46ca-b952-3cdbb312cd57", "status_code": 200, "completed_at": "2026-02-25T11:52:13.895478463+08:00", "client_request_id": ""}
560	2026-02-25 11:52:13.89565+08	info	http.access	http request completed	7eb8ff0c-c66c-41cd-9a5d-84332fd9433d	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/DashboardView-DpyOZDdn.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "7eb8ff0c-c66c-41cd-9a5d-84332fd9433d", "status_code": 200, "completed_at": "2026-02-25T11:52:13.895639462+08:00", "client_request_id": ""}
561	2026-02-25 11:52:13.89596+08	info	http.access	http request completed	61fb403d-f314-4c37-a3f5-adc9aa8f641f	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/LocaleSwitcher-BaVz3FTM.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "61fb403d-f314-4c37-a3f5-adc9aa8f641f", "status_code": 200, "completed_at": "2026-02-25T11:52:13.89595416+08:00", "client_request_id": ""}
562	2026-02-25 11:52:13.896187+08	info	http.access	http request completed	6b8af2ab-abbf-4809-b431-e3a671701eea	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/AppLayout.vue_vue_type_script_setup_true_lang-CbvznAXW.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "6b8af2ab-abbf-4809-b431-e3a671701eea", "status_code": 200, "completed_at": "2026-02-25T11:52:13.896173159+08:00", "client_request_id": ""}
563	2026-02-25 11:52:13.896489+08	info	http.access	http request completed	921e28fc-0ea6-477c-903c-274322f1eaf8	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/LocaleSwitcher-CjvPxOhx.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "921e28fc-0ea6-477c-903c-274322f1eaf8", "status_code": 200, "completed_at": "2026-02-25T11:52:13.896477857+08:00", "client_request_id": ""}
564	2026-02-25 11:52:13.900657+08	info	http.access	http request completed	1e80ed16-a785-4c1c-ab3f-0299cb893600	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 5, "request_id": "1e80ed16-a785-4c1c-ab3f-0299cb893600", "status_code": 200, "completed_at": "2026-02-25T11:52:13.900643732+08:00", "client_request_id": ""}
565	2026-02-25 11:52:13.90925+08	info	http.access	http request completed	fbda80f0-b436-4203-aa84-c27c3f7a6926	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/AppHeader-NeOcFzPI.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "fbda80f0-b436-4203-aa84-c27c3f7a6926", "status_code": 200, "completed_at": "2026-02-25T11:52:13.909230381+08:00", "client_request_id": ""}
566	2026-02-25 11:52:13.909278+08	info	http.access	http request completed	ae5f0527-e960-4522-85a4-1073bc012a67	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/LoadingSpinner-DT-rtrW_.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "ae5f0527-e960-4522-85a4-1073bc012a67", "status_code": 200, "completed_at": "2026-02-25T11:52:13.909249781+08:00", "client_request_id": ""}
567	2026-02-25 11:52:13.909641+08	info	http.access	http request completed	40c8d233-d72f-4298-abb5-42ef9a100f6d	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/DateRangePicker-CFGGkPM1.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "40c8d233-d72f-4298-abb5-42ef9a100f6d", "status_code": 200, "completed_at": "2026-02-25T11:52:13.909624779+08:00", "client_request_id": ""}
568	2026-02-25 11:52:13.913541+08	info	http.access	http request completed	88717d7f-73f7-4a07-bfbc-11f32dfab867	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/Select-7fPaeC0I.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "88717d7f-73f7-4a07-bfbc-11f32dfab867", "status_code": 200, "completed_at": "2026-02-25T11:52:13.913519656+08:00", "client_request_id": ""}
569	2026-02-25 11:52:13.913624+08	info	http.access	http request completed	ec030865-9e10-4fb6-8154-a54b305252bf	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/LoadingSpinner-DI27EpD8.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "ec030865-9e10-4fb6-8154-a54b305252bf", "status_code": 200, "completed_at": "2026-02-25T11:52:13.913604355+08:00", "client_request_id": ""}
570	2026-02-25 11:52:13.913769+08	info	http.access	http request completed	b5c09f43-1c0f-44ab-9e72-17ccec0d7cdb	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/DateRangePicker-WAZB4rcB.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "b5c09f43-1c0f-44ab-9e72-17ccec0d7cdb", "status_code": 200, "completed_at": "2026-02-25T11:52:13.913753554+08:00", "client_request_id": ""}
571	2026-02-25 11:52:13.915281+08	info	http.access	http request completed	c21bb42e-c275-433c-8071-3f09b4ec8241	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/Select-C5iZj_mq.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "c21bb42e-c275-433c-8071-3f09b4ec8241", "status_code": 200, "completed_at": "2026-02-25T11:52:13.915265745+08:00", "client_request_id": ""}
572	2026-02-25 11:52:13.915491+08	info	http.access	http request completed	d9310fe7-610d-43f9-b3a6-d832f87c1f9c	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/TokenUsageTrend.vue_vue_type_script_setup_true_lang-aqjoKx0Q.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "d9310fe7-610d-43f9-b3a6-d832f87c1f9c", "status_code": 200, "completed_at": "2026-02-25T11:52:13.915480044+08:00", "client_request_id": ""}
573	2026-02-25 11:52:13.915624+08	info	http.access	http request completed	bfd11986-d3fc-4951-b47b-e9e65bb0154c	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/vendor-chart-BqAhThnj.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "bfd11986-d3fc-4951-b47b-e9e65bb0154c", "status_code": 200, "completed_at": "2026-02-25T11:52:13.915611243+08:00", "client_request_id": ""}
574	2026-02-25 11:52:13.926444+08	info	http.access	http request completed	777ed578-87ef-42b4-a41f-d0c23efc9fa9	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/EmptyState.vue_vue_type_script_setup_true_lang-BCx0NwKs.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "777ed578-87ef-42b4-a41f-d0c23efc9fa9", "status_code": 200, "completed_at": "2026-02-25T11:52:13.926399279+08:00", "client_request_id": ""}
575	2026-02-25 11:52:13.950839+08	info	http.access	http request completed	56190ce1-f7d0-4d86-98d5-19be46d09d58	\N	\N	\N	\N	\N	{"env": "production", "path": "/logo.png", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "56190ce1-f7d0-4d86-98d5-19be46d09d58", "status_code": 200, "completed_at": "2026-02-25T11:52:13.950794035+08:00", "client_request_id": ""}
576	2026-02-25 11:52:13.956059+08	info	http.access	http request completed	fb8094b7-4da5-44d2-844b-5bd41ad4bd6d	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/subscriptions/active", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 4, "request_id": "fb8094b7-4da5-44d2-844b-5bd41ad4bd6d", "status_code": 200, "completed_at": "2026-02-25T11:52:13.956033903+08:00", "client_request_id": ""}
577	2026-02-25 11:52:13.962926+08	info	http.access	http request completed	e121efb8-a66c-488d-92b7-a82361ae9e71	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/announcements", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 11, "request_id": "e121efb8-a66c-488d-92b7-a82361ae9e71", "status_code": 200, "completed_at": "2026-02-25T11:52:13.962886963+08:00", "client_request_id": ""}
578	2026-02-25 11:52:13.96667+08	info	http.access	http request completed	e8362b6e-0a82-43d6-8187-6b7245f4fca0	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage/dashboard/trend", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "e8362b6e-0a82-43d6-8187-6b7245f4fca0", "status_code": 200, "completed_at": "2026-02-25T11:52:13.966608141+08:00", "client_request_id": ""}
579	2026-02-25 11:52:13.967317+08	info	http.access	http request completed	ff179f15-f2be-4d9f-a4fb-522794b74170	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "ff179f15-f2be-4d9f-a4fb-522794b74170", "status_code": 200, "completed_at": "2026-02-25T11:52:13.967299437+08:00", "client_request_id": ""}
580	2026-02-25 11:52:13.969952+08	info	http.access	http request completed	681501b7-8422-4db2-8e3d-ea8d3cc65731	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage/dashboard/models", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 6, "request_id": "681501b7-8422-4db2-8e3d-ea8d3cc65731", "status_code": 200, "completed_at": "2026-02-25T11:52:13.969915821+08:00", "client_request_id": ""}
581	2026-02-25 11:52:13.976077+08	info	http.access	http request completed	34c1804e-e7ca-42f8-bc71-bb12de28282b	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/KeysView-neHggVFv.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "34c1804e-e7ca-42f8-bc71-bb12de28282b", "status_code": 200, "completed_at": "2026-02-25T11:52:13.976046085+08:00", "client_request_id": ""}
582	2026-02-25 11:52:13.976574+08	info	http.access	http request completed	0dd6ecf0-9a3e-4592-b095-590c97cc8e2a	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/keys-Bav_KspB.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "0dd6ecf0-9a3e-4592-b095-590c97cc8e2a", "status_code": 200, "completed_at": "2026-02-25T11:52:13.976558482+08:00", "client_request_id": ""}
583	2026-02-25 11:52:13.976598+08	info	http.access	http request completed	6ee30aef-206e-40d6-863b-7e48c732ad41	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/useClipboard-DfSApw15.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "6ee30aef-206e-40d6-863b-7e48c732ad41", "status_code": 200, "completed_at": "2026-02-25T11:52:13.976590081+08:00", "client_request_id": ""}
584	2026-02-25 11:52:13.976693+08	info	http.access	http request completed	57dd4864-b84d-4632-a893-ba234c7b5363	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/TablePageLayout-eKTo0RsV.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "57dd4864-b84d-4632-a893-ba234c7b5363", "status_code": 200, "completed_at": "2026-02-25T11:52:13.976675781+08:00", "client_request_id": ""}
585	2026-02-25 11:52:13.97697+08	info	http.access	http request completed	bdd8e731-a1ea-40cb-9467-8efbafa61b52	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/TablePageLayout-aLZmGbo3.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "bdd8e731-a1ea-40cb-9467-8efbafa61b52", "status_code": 200, "completed_at": "2026-02-25T11:52:13.976964279+08:00", "client_request_id": ""}
586	2026-02-25 11:52:13.977218+08	info	http.access	http request completed	d8d9875e-8f20-4fbd-82ca-0f9252941a0e	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 4, "request_id": "d8d9875e-8f20-4fbd-82ca-0f9252941a0e", "status_code": 200, "completed_at": "2026-02-25T11:52:13.977205878+08:00", "client_request_id": ""}
587	2026-02-25 11:52:13.983471+08	info	http.access	http request completed	a4cf1beb-8d8b-45a5-9c4a-54e87447805f	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/DataTable-wk4w1kiu.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "a4cf1beb-8d8b-45a5-9c4a-54e87447805f", "status_code": 200, "completed_at": "2026-02-25T11:52:13.983449741+08:00", "client_request_id": ""}
588	2026-02-25 11:52:13.985422+08	info	http.access	http request completed	15f9f81f-8a39-4fae-aa34-04e4d8f935c7	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/Pagination-DtcDDVEA.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "15f9f81f-8a39-4fae-aa34-04e4d8f935c7", "status_code": 200, "completed_at": "2026-02-25T11:52:13.985408329+08:00", "client_request_id": ""}
589	2026-02-25 11:52:13.986024+08	info	http.access	http request completed	e7cb80df-de6e-41a4-89e3-f46d5e9a7b32	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/DataTable-CMXPVGQy.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "e7cb80df-de6e-41a4-89e3-f46d5e9a7b32", "status_code": 200, "completed_at": "2026-02-25T11:52:13.986011626+08:00", "client_request_id": ""}
590	2026-02-25 11:52:13.986042+08	info	http.access	http request completed	1bf33f67-ecf8-4945-9b44-5adcb2fe34ed	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/Pagination-FUaRDcBY.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "1bf33f67-ecf8-4945-9b44-5adcb2fe34ed", "status_code": 200, "completed_at": "2026-02-25T11:52:13.986031425+08:00", "client_request_id": ""}
591	2026-02-25 11:52:13.986063+08	info	http.access	http request completed	21233bd3-a7fa-4dac-8e18-bf390f1792e0	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/GroupBadge.vue_vue_type_script_setup_true_lang-Cej1HtUK.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "21233bd3-a7fa-4dac-8e18-bf390f1792e0", "status_code": 200, "completed_at": "2026-02-25T11:52:13.986052025+08:00", "client_request_id": ""}
592	2026-02-25 11:52:13.986133+08	info	http.access	http request completed	23773e40-d83a-4e89-be96-d28e9961d620	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/ConfirmDialog.vue_vue_type_script_setup_true_lang-Dlp3dUO2.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "23773e40-d83a-4e89-be96-d28e9961d620", "status_code": 200, "completed_at": "2026-02-25T11:52:13.986121125+08:00", "client_request_id": ""}
593	2026-02-25 11:52:13.989599+08	info	http.access	http request completed	06186e60-8ead-4afa-a14c-45dd17cc285d	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/GroupOptionItem.vue_vue_type_script_setup_true_lang-DJgQlkUJ.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "06186e60-8ead-4afa-a14c-45dd17cc285d", "status_code": 200, "completed_at": "2026-02-25T11:52:13.989582904+08:00", "client_request_id": ""}
594	2026-02-25 11:52:13.989832+08	info	http.access	http request completed	bbb5dfed-0805-4f24-93d9-3d7ae9f2ce8e	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/PlatformIcon.vue_vue_type_script_setup_true_lang-DDJ5Ol8Z.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "bbb5dfed-0805-4f24-93d9-3d7ae9f2ce8e", "status_code": 200, "completed_at": "2026-02-25T11:52:13.989812303+08:00", "client_request_id": ""}
595	2026-02-25 11:52:13.990132+08	info	http.access	http request completed	2fbeef36-3665-4f06-86da-abf23c389dec	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/UsageView-CYHjTYYV.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "2fbeef36-3665-4f06-86da-abf23c389dec", "status_code": 200, "completed_at": "2026-02-25T11:52:13.990115701+08:00", "client_request_id": ""}
596	2026-02-25 11:52:14.000067+08	info	http.access	http request completed	9c5dccb0-2252-49e5-8f21-f0b3dc87095b	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage/dashboard/stats", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 9, "request_id": "9c5dccb0-2252-49e5-8f21-f0b3dc87095b", "status_code": 200, "completed_at": "2026-02-25T11:52:14.000013443+08:00", "client_request_id": ""}
597	2026-02-25 11:52:14.713396+08	info	http.access	http request completed	1aac9d8b-96d6-4ddf-a47a-98f9c35ba180	\N	\N	\N	\N	\N	{"env": "production", "path": "/dashboard", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "1aac9d8b-96d6-4ddf-a47a-98f9c35ba180", "status_code": 304, "completed_at": "2026-02-25T11:52:14.71338291+08:00", "client_request_id": ""}
598	2026-02-25 11:52:14.733721+08	info	http.access	http request completed	f0042c9b-8057-4218-acd1-40b7d22284ff	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/vendor-i18n-CF5oKjnm.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "f0042c9b-8057-4218-acd1-40b7d22284ff", "status_code": 200, "completed_at": "2026-02-25T11:52:14.733700089+08:00", "client_request_id": ""}
599	2026-02-25 11:52:14.733722+08	info	http.access	http request completed	bc0dfa77-c559-4f34-b216-107ce0d67e9a	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/index-CkKnxzIb.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "bc0dfa77-c559-4f34-b216-107ce0d67e9a", "status_code": 200, "completed_at": "2026-02-25T11:52:14.733704589+08:00", "client_request_id": ""}
600	2026-02-25 11:52:14.733828+08	info	http.access	http request completed	8f14238e-79ab-45fa-8947-d165aa9d43d7	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/vendor-vue-4WNFgugS.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "8f14238e-79ab-45fa-8947-d165aa9d43d7", "status_code": 200, "completed_at": "2026-02-25T11:52:14.733815088+08:00", "client_request_id": ""}
601	2026-02-25 11:52:14.733832+08	info	http.access	http request completed	54d88550-a8d7-4b0f-9ee5-e30ef1e3d091	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/vendor-misc-DB0Q8XAf.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "54d88550-a8d7-4b0f-9ee5-e30ef1e3d091", "status_code": 200, "completed_at": "2026-02-25T11:52:14.733811288+08:00", "client_request_id": ""}
602	2026-02-25 11:52:14.733856+08	info	http.access	http request completed	0baf5f92-ab6a-4b45-b037-ac0ce6d534ea	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/vendor-misc-NmuJm1mp.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "0baf5f92-ab6a-4b45-b037-ac0ce6d534ea", "status_code": 200, "completed_at": "2026-02-25T11:52:14.733845088+08:00", "client_request_id": ""}
603	2026-02-25 11:52:14.734258+08	info	http.access	http request completed	22c1ce5b-40a3-4cee-9dbb-b318fc2a2002	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/index-Dji9Snxu.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "22c1ce5b-40a3-4cee-9dbb-b318fc2a2002", "status_code": 200, "completed_at": "2026-02-25T11:52:14.734245686+08:00", "client_request_id": ""}
604	2026-02-25 11:52:14.793705+08	info	http.access	http request completed	bc21295d-67a7-4f28-abbe-515b8ef2c534	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/zh-joyDK6VH.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "bc21295d-67a7-4f28-abbe-515b8ef2c534", "status_code": 200, "completed_at": "2026-02-25T11:52:14.793688433+08:00", "client_request_id": ""}
605	2026-02-25 11:52:14.794823+08	info	http.access	http request completed	48ddbba0-ceaf-4ab2-b8ae-6d65df3623b6	\N	\N	\N	\N	\N	{"env": "production", "path": "/logo.png", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "48ddbba0-ceaf-4ab2-b8ae-6d65df3623b6", "status_code": 200, "completed_at": "2026-02-25T11:52:14.794800926+08:00", "client_request_id": ""}
606	2026-02-25 11:52:14.82782+08	info	http.access	http request completed	5b1957f0-5ec9-4811-95c3-645728e5d337	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/DashboardView-DpyOZDdn.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "5b1957f0-5ec9-4811-95c3-645728e5d337", "status_code": 200, "completed_at": "2026-02-25T11:52:14.827802631+08:00", "client_request_id": ""}
607	2026-02-25 11:52:14.828018+08	info	http.access	http request completed	2cd26892-825e-4a8d-8ccd-16db715cb0ba	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/usage-DjeCvF1i.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "2cd26892-825e-4a8d-8ccd-16db715cb0ba", "status_code": 200, "completed_at": "2026-02-25T11:52:14.828005729+08:00", "client_request_id": ""}
608	2026-02-25 11:52:14.828431+08	info	http.access	http request completed	9191c319-b19c-4af7-b710-3c178ebe76c0	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/LocaleSwitcher-BaVz3FTM.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "9191c319-b19c-4af7-b710-3c178ebe76c0", "status_code": 200, "completed_at": "2026-02-25T11:52:14.828411327+08:00", "client_request_id": ""}
609	2026-02-25 11:52:14.828488+08	info	http.access	http request completed	f22405b1-bc5b-471b-9249-1cf9661d219f	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/AppLayout.vue_vue_type_script_setup_true_lang-CbvznAXW.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "f22405b1-bc5b-471b-9249-1cf9661d219f", "status_code": 200, "completed_at": "2026-02-25T11:52:14.828470027+08:00", "client_request_id": ""}
610	2026-02-25 11:52:14.829029+08	info	http.access	http request completed	488696a9-a81c-4a7e-9b0e-25dd5ffc3f34	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/LocaleSwitcher-CjvPxOhx.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "488696a9-a81c-4a7e-9b0e-25dd5ffc3f34", "status_code": 200, "completed_at": "2026-02-25T11:52:14.829011123+08:00", "client_request_id": ""}
611	2026-02-25 11:52:14.83066+08	info	http.access	http request completed	ab419189-e639-47e8-9192-a8820758da12	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 4, "request_id": "ab419189-e639-47e8-9192-a8820758da12", "status_code": 200, "completed_at": "2026-02-25T11:52:14.830640714+08:00", "client_request_id": ""}
612	2026-02-25 11:52:14.842285+08	info	http.access	http request completed	9768f024-7cd9-408b-9d2b-72d9b5ad8acb	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/LoadingSpinner-DT-rtrW_.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "9768f024-7cd9-408b-9d2b-72d9b5ad8acb", "status_code": 200, "completed_at": "2026-02-25T11:52:14.842268945+08:00", "client_request_id": ""}
613	2026-02-25 11:52:14.842348+08	info	http.access	http request completed	1bf48944-1e80-4dad-97e2-23c6ab0b5a31	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/AppHeader-NeOcFzPI.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "1bf48944-1e80-4dad-97e2-23c6ab0b5a31", "status_code": 200, "completed_at": "2026-02-25T11:52:14.842334244+08:00", "client_request_id": ""}
614	2026-02-25 11:52:14.845552+08	info	http.access	http request completed	4b2dfe43-db1b-497d-ba67-14dea6a78caf	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/LoadingSpinner-DI27EpD8.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "4b2dfe43-db1b-497d-ba67-14dea6a78caf", "status_code": 200, "completed_at": "2026-02-25T11:52:14.845516026+08:00", "client_request_id": ""}
615	2026-02-25 11:52:14.845637+08	info	http.access	http request completed	ac87dbba-b3f8-4d1d-856f-29e4a60b4c71	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/Select-7fPaeC0I.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "ac87dbba-b3f8-4d1d-856f-29e4a60b4c71", "status_code": 200, "completed_at": "2026-02-25T11:52:14.845625525+08:00", "client_request_id": ""}
616	2026-02-25 11:52:14.84555+08	info	http.access	http request completed	eef0e9b5-138a-4762-8daf-f5c400a8f704	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/DateRangePicker-CFGGkPM1.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "eef0e9b5-138a-4762-8daf-f5c400a8f704", "status_code": 200, "completed_at": "2026-02-25T11:52:14.845525525+08:00", "client_request_id": ""}
617	2026-02-25 11:52:14.845564+08	info	http.access	http request completed	8ec9969f-0cf6-4263-a558-00c938b8ee92	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/DateRangePicker-WAZB4rcB.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "8ec9969f-0cf6-4263-a558-00c938b8ee92", "status_code": 200, "completed_at": "2026-02-25T11:52:14.845554425+08:00", "client_request_id": ""}
618	2026-02-25 11:52:14.847967+08	info	http.access	http request completed	ad8c1009-ee24-413f-9dd3-5c0c66891e58	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/Select-C5iZj_mq.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "ad8c1009-ee24-413f-9dd3-5c0c66891e58", "status_code": 200, "completed_at": "2026-02-25T11:52:14.847948611+08:00", "client_request_id": ""}
619	2026-02-25 11:52:14.848295+08	info	http.access	http request completed	690d60cf-9c52-45b8-81db-c3020f8a4b00	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/vendor-chart-BqAhThnj.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "690d60cf-9c52-45b8-81db-c3020f8a4b00", "status_code": 200, "completed_at": "2026-02-25T11:52:14.848276709+08:00", "client_request_id": ""}
620	2026-02-25 11:52:14.849475+08	info	http.access	http request completed	88e58d66-866f-43da-8afd-1d52b853e4e7	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/EmptyState.vue_vue_type_script_setup_true_lang-BCx0NwKs.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "88e58d66-866f-43da-8afd-1d52b853e4e7", "status_code": 200, "completed_at": "2026-02-25T11:52:14.849464502+08:00", "client_request_id": ""}
621	2026-02-25 11:52:14.849417+08	info	http.access	http request completed	6261b6e3-e4f0-4f2a-9e2b-3474ce1d704a	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/TokenUsageTrend.vue_vue_type_script_setup_true_lang-aqjoKx0Q.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "6261b6e3-e4f0-4f2a-9e2b-3474ce1d704a", "status_code": 200, "completed_at": "2026-02-25T11:52:14.849404302+08:00", "client_request_id": ""}
622	2026-02-25 11:52:14.910096+08	info	http.access	http request completed	06ca709b-24b4-4dc1-b6d7-89b2c0ed3284	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/subscriptions/active", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 4, "request_id": "06ca709b-24b4-4dc1-b6d7-89b2c0ed3284", "status_code": 200, "completed_at": "2026-02-25T11:52:14.910050543+08:00", "client_request_id": ""}
623	2026-02-25 11:52:14.910286+08	info	http.access	http request completed	57e0a520-d4a3-47b0-ae43-740c47c96027	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage/dashboard/trend", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 4, "request_id": "57e0a520-d4a3-47b0-ae43-740c47c96027", "status_code": 200, "completed_at": "2026-02-25T11:52:14.910257341+08:00", "client_request_id": ""}
624	2026-02-25 11:52:14.912539+08	info	http.access	http request completed	f39996af-2f41-4083-a8fe-471662fac9ae	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage/dashboard/models", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 6, "request_id": "f39996af-2f41-4083-a8fe-471662fac9ae", "status_code": 200, "completed_at": "2026-02-25T11:52:14.912523228+08:00", "client_request_id": ""}
625	2026-02-25 11:52:14.913714+08	info	http.access	http request completed	eee75599-95e4-4349-a3dd-88e60640496e	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 7, "request_id": "eee75599-95e4-4349-a3dd-88e60640496e", "status_code": 200, "completed_at": "2026-02-25T11:52:14.913686521+08:00", "client_request_id": ""}
626	2026-02-25 11:52:14.914395+08	info	http.access	http request completed	20f63925-6d29-43ce-a01b-ce87064a0197	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/TablePageLayout-eKTo0RsV.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "20f63925-6d29-43ce-a01b-ce87064a0197", "status_code": 200, "completed_at": "2026-02-25T11:52:14.914370217+08:00", "client_request_id": ""}
627	2026-02-25 11:52:14.914705+08	info	http.access	http request completed	f5dab091-6207-4c28-aa59-6e40ba175f32	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/DataTable-wk4w1kiu.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "f5dab091-6207-4c28-aa59-6e40ba175f32", "status_code": 200, "completed_at": "2026-02-25T11:52:14.914691615+08:00", "client_request_id": ""}
628	2026-02-25 11:52:14.915945+08	info	http.access	http request completed	80b29a29-2416-4cf6-9b2a-336d4651aa64	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/Pagination-DtcDDVEA.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "80b29a29-2416-4cf6-9b2a-336d4651aa64", "status_code": 200, "completed_at": "2026-02-25T11:52:14.915932108+08:00", "client_request_id": ""}
629	2026-02-25 11:52:14.91659+08	info	http.access	http request completed	a0117654-af3e-4f22-8f5a-bc5849669ae4	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/KeysView-neHggVFv.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "a0117654-af3e-4f22-8f5a-bc5849669ae4", "status_code": 200, "completed_at": "2026-02-25T11:52:14.916571704+08:00", "client_request_id": ""}
630	2026-02-25 11:52:14.916899+08	info	http.access	http request completed	3009a21e-d5e3-42c0-bf2e-498e71c9d558	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/announcements", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 10, "request_id": "3009a21e-d5e3-42c0-bf2e-498e71c9d558", "status_code": 200, "completed_at": "2026-02-25T11:52:14.916885702+08:00", "client_request_id": ""}
631	2026-02-25 11:52:14.917226+08	info	http.access	http request completed	6c49fb8f-eb50-4d5b-b8c7-5f5917fdf9c6	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/useClipboard-DfSApw15.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "6c49fb8f-eb50-4d5b-b8c7-5f5917fdf9c6", "status_code": 200, "completed_at": "2026-02-25T11:52:14.9172161+08:00", "client_request_id": ""}
632	2026-02-25 11:52:14.918004+08	info	http.access	http request completed	f6b68484-2110-4b70-ba1b-6e26baf5761f	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/keys-Bav_KspB.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "f6b68484-2110-4b70-ba1b-6e26baf5761f", "status_code": 200, "completed_at": "2026-02-25T11:52:14.917982896+08:00", "client_request_id": ""}
633	2026-02-25 11:52:14.918043+08	info	http.access	http request completed	3ac40627-2e11-48b2-9d89-1e41b0f68a63	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 11, "request_id": "3ac40627-2e11-48b2-9d89-1e41b0f68a63", "status_code": 200, "completed_at": "2026-02-25T11:52:14.918024295+08:00", "client_request_id": ""}
634	2026-02-25 11:52:14.922837+08	info	http.access	http request completed	fc5d8452-afdd-45b7-9246-d42983d8b70f	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/TablePageLayout-aLZmGbo3.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "fc5d8452-afdd-45b7-9246-d42983d8b70f", "status_code": 200, "completed_at": "2026-02-25T11:52:14.922807567+08:00", "client_request_id": ""}
635	2026-02-25 11:52:14.923561+08	info	http.access	http request completed	83654c35-e39f-47c0-9865-4b9aa178341c	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/DataTable-CMXPVGQy.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "83654c35-e39f-47c0-9865-4b9aa178341c", "status_code": 200, "completed_at": "2026-02-25T11:52:14.923537863+08:00", "client_request_id": ""}
636	2026-02-25 11:52:14.926517+08	info	http.access	http request completed	52bdbe42-3e6f-486b-95f6-c406d92c8884	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/GroupBadge.vue_vue_type_script_setup_true_lang-Cej1HtUK.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "52bdbe42-3e6f-486b-95f6-c406d92c8884", "status_code": 200, "completed_at": "2026-02-25T11:52:14.926486445+08:00", "client_request_id": ""}
637	2026-02-25 11:52:14.926524+08	info	http.access	http request completed	bd708d8a-e936-493b-99ba-8149210437c6	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/Pagination-FUaRDcBY.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "bd708d8a-e936-493b-99ba-8149210437c6", "status_code": 200, "completed_at": "2026-02-25T11:52:14.926510045+08:00", "client_request_id": ""}
638	2026-02-25 11:52:14.926521+08	info	http.access	http request completed	b0c9c7f7-a6c5-4a94-9644-bb26e98d8ff0	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/ConfirmDialog.vue_vue_type_script_setup_true_lang-Dlp3dUO2.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "b0c9c7f7-a6c5-4a94-9644-bb26e98d8ff0", "status_code": 200, "completed_at": "2026-02-25T11:52:14.926514045+08:00", "client_request_id": ""}
639	2026-02-25 11:52:14.926712+08	info	http.access	http request completed	04c7541a-3f65-4125-9b66-97180b1aa403	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/PlatformIcon.vue_vue_type_script_setup_true_lang-DDJ5Ol8Z.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "04c7541a-3f65-4125-9b66-97180b1aa403", "status_code": 200, "completed_at": "2026-02-25T11:52:14.926700144+08:00", "client_request_id": ""}
640	2026-02-25 11:52:14.928147+08	info	http.access	http request completed	8e10f3f8-db24-4d2e-8c8c-e6f2c220e0ef	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/GroupOptionItem.vue_vue_type_script_setup_true_lang-DJgQlkUJ.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "8e10f3f8-db24-4d2e-8c8c-e6f2c220e0ef", "status_code": 200, "completed_at": "2026-02-25T11:52:14.928126535+08:00", "client_request_id": ""}
641	2026-02-25 11:52:14.929009+08	info	http.access	http request completed	a61e855c-10f8-4fec-ba1e-f0fe6b8ffec7	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/UsageView-CYHjTYYV.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "a61e855c-10f8-4fec-ba1e-f0fe6b8ffec7", "status_code": 200, "completed_at": "2026-02-25T11:52:14.92899613+08:00", "client_request_id": ""}
642	2026-02-25 11:52:14.946257+08	info	http.access	http request completed	2c32befb-a245-4a54-abfc-2a54a8b55efa	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/settings/public", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 4, "request_id": "2c32befb-a245-4a54-abfc-2a54a8b55efa", "status_code": 200, "completed_at": "2026-02-25T11:52:14.946221128+08:00", "client_request_id": ""}
643	2026-02-25 11:52:14.953765+08	info	http.access	http request completed	e08a742a-cd52-46a3-881f-a69353cbba92	\N	\N	\N	\N	\N	{"env": "production", "path": "/logo.png", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "e08a742a-cd52-46a3-881f-a69353cbba92", "status_code": 200, "completed_at": "2026-02-25T11:52:14.953719483+08:00", "client_request_id": ""}
644	2026-02-25 11:52:14.958831+08	info	http.access	http request completed	932a0160-e57f-4aac-95c6-24abe7b67453	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage/dashboard/stats", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 14, "request_id": "932a0160-e57f-4aac-95c6-24abe7b67453", "status_code": 200, "completed_at": "2026-02-25T11:52:14.958803453+08:00", "client_request_id": ""}
645	2026-02-25 11:52:18.520571+08	info	http.access	http request completed	292adac1-17a8-4995-bf7b-2e635e1086e3	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/logout", "method": "POST", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "292adac1-17a8-4995-bf7b-2e635e1086e3", "status_code": 200, "completed_at": "2026-02-25T11:52:18.520550419+08:00", "client_request_id": ""}
646	2026-02-25 11:52:18.526553+08	info	http.access	http request completed	f63ec6e6-2a57-4597-91ea-4f1446d543e3	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/AuthLayout-DuqqvlHK.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "f63ec6e6-2a57-4597-91ea-4f1446d543e3", "status_code": 200, "completed_at": "2026-02-25T11:52:18.526542383+08:00", "client_request_id": ""}
647	2026-02-25 11:52:18.526648+08	info	http.access	http request completed	60448898-a0c2-4079-a2b3-76aed3d420be	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/LoginView-sMz7fVWw.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "60448898-a0c2-4079-a2b3-76aed3d420be", "status_code": 200, "completed_at": "2026-02-25T11:52:18.526609383+08:00", "client_request_id": ""}
648	2026-02-25 11:52:18.526772+08	info	http.access	http request completed	68253610-625a-47e6-a42d-0b9fcb0d48dd	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/AuthLayout-BLY8cBK0.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "68253610-625a-47e6-a42d-0b9fcb0d48dd", "status_code": 200, "completed_at": "2026-02-25T11:52:18.526756282+08:00", "client_request_id": ""}
649	2026-02-25 11:52:18.526921+08	info	http.access	http request completed	95856347-2ebe-4562-8928-9d02fda4e78b	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/TurnstileWidget-CtZXX_iR.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "95856347-2ebe-4562-8928-9d02fda4e78b", "status_code": 200, "completed_at": "2026-02-25T11:52:18.526905981+08:00", "client_request_id": ""}
650	2026-02-25 11:52:18.526961+08	info	http.access	http request completed	d018c17b-a52b-4fa6-96f2-a9afebd1829f	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/TurnstileWidget-CsDyAChT.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "d018c17b-a52b-4fa6-96f2-a9afebd1829f", "status_code": 200, "completed_at": "2026-02-25T11:52:18.526949781+08:00", "client_request_id": ""}
651	2026-02-25 11:52:18.526985+08	info	http.access	http request completed	d63c713f-8ade-46b0-800b-59cc601a0638	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/LinuxDoOAuthSection.vue_vue_type_script_setup_true_lang-DJujUfeo.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "d63c713f-8ade-46b0-800b-59cc601a0638", "status_code": 200, "completed_at": "2026-02-25T11:52:18.526911981+08:00", "client_request_id": ""}
652	2026-02-25 11:52:18.528227+08	info	http.access	http request completed	f17f75b3-5dc0-48fe-99d4-704b313d0a97	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/LoginView-CM0iaiMq.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "f17f75b3-5dc0-48fe-99d4-704b313d0a97", "status_code": 200, "completed_at": "2026-02-25T11:52:18.528218073+08:00", "client_request_id": ""}
653	2026-02-25 11:52:18.547052+08	info	http.access	http request completed	adda5ac1-a41b-4343-833a-7b085bbcb1d8	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/settings/public", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "adda5ac1-a41b-4343-833a-7b085bbcb1d8", "status_code": 200, "completed_at": "2026-02-25T11:52:18.547015562+08:00", "client_request_id": ""}
654	2026-02-25 11:52:21.998072+08	info	http.access	http request completed	c0710af1-5729-43cc-9688-f1b9bc3eee91	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/login", "method": "POST", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 52, "request_id": "c0710af1-5729-43cc-9688-f1b9bc3eee91", "status_code": 200, "completed_at": "2026-02-25T11:52:21.998059093+08:00", "client_request_id": ""}
655	2026-02-25 11:52:22.005145+08	info	http.access	http request completed	1b72dc70-6107-4f00-ad97-e80c1f0838db	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/subscriptions/active", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "1b72dc70-6107-4f00-ad97-e80c1f0838db", "status_code": 200, "completed_at": "2026-02-25T11:52:22.005112951+08:00", "client_request_id": ""}
656	2026-02-25 11:52:22.020313+08	info	http.access	http request completed	9dbb309f-eb42-4e94-84bc-432f08a98c34	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/settings", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "9dbb309f-eb42-4e94-84bc-432f08a98c34", "status_code": 200, "completed_at": "2026-02-25T11:52:22.020288862+08:00", "client_request_id": ""}
657	2026-02-25 11:52:22.020356+08	info	http.access	http request completed	2bd23141-3784-4745-9001-04ba49d020ce	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage/dashboard/models", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "2bd23141-3784-4745-9001-04ba49d020ce", "status_code": 200, "completed_at": "2026-02-25T11:52:22.020342061+08:00", "client_request_id": ""}
658	2026-02-25 11:52:22.021263+08	info	http.access	http request completed	f5351178-402d-4d08-a925-4307c92f630c	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "f5351178-402d-4d08-a925-4307c92f630c", "status_code": 200, "completed_at": "2026-02-25T11:52:22.021240756+08:00", "client_request_id": ""}
659	2026-02-25 11:52:22.022046+08	info	http.access	http request completed	71d91a53-acf5-413d-ae4f-7a5494e1a30d	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage/dashboard/trend", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 4, "request_id": "71d91a53-acf5-413d-ae4f-7a5494e1a30d", "status_code": 200, "completed_at": "2026-02-25T11:52:22.021999451+08:00", "client_request_id": ""}
660	2026-02-25 11:52:22.024434+08	info	http.access	http request completed	63ba5e6d-fdc3-4440-9fd1-e03cf3a31cb2	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/announcements", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 7, "request_id": "63ba5e6d-fdc3-4440-9fd1-e03cf3a31cb2", "status_code": 200, "completed_at": "2026-02-25T11:52:22.024393537+08:00", "client_request_id": ""}
661	2026-02-25 11:52:22.027598+08	info	http.access	http request completed	6df9c763-eab8-4fd6-9904-aeb7761c9efc	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 4, "request_id": "6df9c763-eab8-4fd6-9904-aeb7761c9efc", "status_code": 200, "completed_at": "2026-02-25T11:52:22.027543219+08:00", "client_request_id": ""}
662	2026-02-25 11:52:22.036106+08	info	http.access	http request completed	670d7cde-c69e-4416-931a-2d51cff03095	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/usage/dashboard/stats", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 4, "request_id": "670d7cde-c69e-4416-931a-2d51cff03095", "status_code": 200, "completed_at": "2026-02-25T11:52:22.036087268+08:00", "client_request_id": ""}
663	2026-02-25 11:52:22.576106+08	info	http.access	http request completed	ef50577b-ac10-41bc-a818-bda520802662	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/system/check-updates", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 558, "request_id": "ef50577b-ac10-41bc-a818-bda520802662", "status_code": 200, "completed_at": "2026-02-25T11:52:22.576086773+08:00", "client_request_id": ""}
664	2026-02-25 11:52:56.12875+08	error	stdlog	[ERROR] POST /api/v1/admin/system/update Error: download failed: context canceled	\N	\N	\N	\N	\N	\N	{"env": "production", "service": "sub2api", "legacy_stdlog": true}
665	2026-02-25 11:52:56.128899+08	info	http.access	http request completed	66022269-a222-423f-ac6b-87aeb665c653	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/system/update", "method": "POST", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 30007, "request_id": "66022269-a222-423f-ac6b-87aeb665c653", "status_code": 500, "completed_at": "2026-02-25T11:52:56.12888469+08:00", "client_request_id": ""}
666	2026-02-25 11:53:22.006093+08	info	http.access	http request completed	daea9d10-e4c5-4833-9297-34251470db0c	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "daea9d10-e4c5-4833-9297-34251470db0c", "status_code": 200, "completed_at": "2026-02-25T11:53:22.006078951+08:00", "client_request_id": ""}
667	2026-02-25 11:54:22.007925+08	info	http.access	http request completed	36275218-c80a-4bec-8387-f9526d1ae3c9	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "36275218-c80a-4bec-8387-f9526d1ae3c9", "status_code": 200, "completed_at": "2026-02-25T11:54:22.007911001+08:00", "client_request_id": ""}
668	2026-02-25 11:55:22.00426+08	info	http.access	http request completed	50375d84-08a4-4ad5-813f-942e8e2a83f6	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "50375d84-08a4-4ad5-813f-942e8e2a83f6", "status_code": 200, "completed_at": "2026-02-25T11:55:22.004244371+08:00", "client_request_id": ""}
669	2026-02-25 11:56:02.904377+08	info	http.access	http request completed	3d6f6f23-60c5-412c-81a1-a3adb12e9197	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/SettingsView-59zWuNEo.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "3d6f6f23-60c5-412c-81a1-a3adb12e9197", "status_code": 200, "completed_at": "2026-02-25T11:56:02.904348651+08:00", "client_request_id": ""}
670	2026-02-25 11:56:02.905556+08	info	http.access	http request completed	aa713dab-a000-4936-9b09-7d0f763318a3	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/Toggle.vue_vue_type_script_setup_true_lang-B0FKZlYT.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "aa713dab-a000-4936-9b09-7d0f763318a3", "status_code": 200, "completed_at": "2026-02-25T11:56:02.905549344+08:00", "client_request_id": ""}
671	2026-02-25 11:56:02.936003+08	info	http.access	http request completed	bb90098a-204d-4c76-995a-104270430340	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/settings", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "bb90098a-204d-4c76-995a-104270430340", "status_code": 200, "completed_at": "2026-02-25T11:56:02.935988367+08:00", "client_request_id": ""}
672	2026-02-25 11:56:02.936054+08	info	http.access	http request completed	29146ccc-6826-480a-8871-2b558a6d99eb	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/subscriptions/active", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 4, "request_id": "29146ccc-6826-480a-8871-2b558a6d99eb", "status_code": 200, "completed_at": "2026-02-25T11:56:02.936042467+08:00", "client_request_id": ""}
673	2026-02-25 11:56:02.936466+08	info	http.access	http request completed	fc176707-ec96-4d29-93e9-2abe31d5c177	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/settings/admin-api-key", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "fc176707-ec96-4d29-93e9-2abe31d5c177", "status_code": 200, "completed_at": "2026-02-25T11:56:02.936453365+08:00", "client_request_id": ""}
674	2026-02-25 11:56:02.937373+08	info	http.access	http request completed	b76f9cb8-bd9d-4d05-9051-78f8c2e6f09a	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/settings/stream-timeout", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "b76f9cb8-bd9d-4d05-9051-78f8c2e6f09a", "status_code": 200, "completed_at": "2026-02-25T11:56:02.937360059+08:00", "client_request_id": ""}
675	2026-02-25 11:56:02.938917+08	info	http.access	http request completed	270442fe-0ca1-4f86-9f23-01b15609f0e8	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/announcements", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 7, "request_id": "270442fe-0ca1-4f86-9f23-01b15609f0e8", "status_code": 200, "completed_at": "2026-02-25T11:56:02.93889075+08:00", "client_request_id": ""}
676	2026-02-25 11:56:06.464003+08	info	http.access	http request completed	f7949876-9dcd-4d19-9ce0-6d0b64a532b7	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/settings/ldap/test", "method": "POST", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 10, "request_id": "f7949876-9dcd-4d19-9ce0-6d0b64a532b7", "status_code": 200, "completed_at": "2026-02-25T11:56:06.463982025+08:00", "client_request_id": ""}
677	2026-02-25 11:56:22.00412+08	info	http.access	http request completed	a6afe8a4-7d39-41c2-ae5b-bd72026c1f20	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "a6afe8a4-7d39-41c2-ae5b-bd72026c1f20", "status_code": 200, "completed_at": "2026-02-25T11:56:22.004106909+08:00", "client_request_id": ""}
678	2026-02-25 11:56:53.639248+08	info	http.access	http request completed	590802cd-3ae6-4b29-8041-5e367e407d0d	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/stableObjectKey-DullU5Fx.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "590802cd-3ae6-4b29-8041-5e367e407d0d", "status_code": 200, "completed_at": "2026-02-25T11:56:53.639238506+08:00", "client_request_id": ""}
679	2026-02-25 11:56:53.639591+08	info	http.access	http request completed	ce159d0e-83d7-45ab-9a96-815b34d24de4	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/GroupsView-RO5Ym38B.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "ce159d0e-83d7-45ab-9a96-815b34d24de4", "status_code": 200, "completed_at": "2026-02-25T11:56:53.639578604+08:00", "client_request_id": ""}
680	2026-02-25 11:56:53.687309+08	info	http.access	http request completed	5df7ae58-b9c7-4841-871d-7199988c5886	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/groups", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "5df7ae58-b9c7-4841-871d-7199988c5886", "status_code": 200, "completed_at": "2026-02-25T11:56:53.687292627+08:00", "client_request_id": ""}
681	2026-02-25 11:56:53.687422+08	info	http.access	http request completed	439980fe-305e-4526-859f-f3b4dcfe0bea	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/announcements", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 4, "request_id": "439980fe-305e-4526-859f-f3b4dcfe0bea", "status_code": 200, "completed_at": "2026-02-25T11:56:53.687383326+08:00", "client_request_id": ""}
715	2026-02-25 12:04:27.083827+08	info	http.access	http request completed	632b9d66-f5ac-42e2-8bb2-df20aac37ea8	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "632b9d66-f5ac-42e2-8bb2-df20aac37ea8", "status_code": 200, "completed_at": "2026-02-25T12:04:27.083810297+08:00", "client_request_id": ""}
682	2026-02-25 11:56:53.716568+08	info	http.access	http request completed	579f5495-8ad6-4d75-8ace-11fd8792f734	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/SubscriptionsView-z7fdEfWj.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "579f5495-8ad6-4d75-8ace-11fd8792f734", "status_code": 200, "completed_at": "2026-02-25T11:56:53.716488057+08:00", "client_request_id": ""}
683	2026-02-25 11:56:53.716993+08	info	http.access	http request completed	578f6968-505e-482f-b2c7-dd265d165260	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/SubscriptionsView-DBamVQ7h.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "578f6968-505e-482f-b2c7-dd265d165260", "status_code": 200, "completed_at": "2026-02-25T11:56:53.716973254+08:00", "client_request_id": ""}
684	2026-02-25 11:56:53.717052+08	info	http.access	http request completed	177fb53e-5ab7-4174-99cd-eb0c3e80de4c	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/UsersView-qOd5hN3-.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "177fb53e-5ab7-4174-99cd-eb0c3e80de4c", "status_code": 200, "completed_at": "2026-02-25T11:56:53.717040354+08:00", "client_request_id": ""}
685	2026-02-25 11:56:53.717434+08	info	http.access	http request completed	750a69b6-cbc5-40ad-87e1-3ebca0525840	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/UsersView-CXOILkvl.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "750a69b6-cbc5-40ad-87e1-3ebca0525840", "status_code": 200, "completed_at": "2026-02-25T11:56:53.717418951+08:00", "client_request_id": ""}
686	2026-02-25 11:57:15.80957+08	info	http.access	http request completed	0b26ce72-41c7-4b59-ae5f-ca7e5ad4a302	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/ModelDistributionChart.vue_vue_type_script_setup_true_lang-CQ7dGsGe.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "0b26ce72-41c7-4b59-ae5f-ca7e5ad4a302", "status_code": 200, "completed_at": "2026-02-25T11:57:15.80956088+08:00", "client_request_id": ""}
687	2026-02-25 11:57:15.8097+08	info	http.access	http request completed	63e75016-f09e-481e-b9ff-0ba664f5adc0	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/DashboardView-BvobUzeR.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "63e75016-f09e-481e-b9ff-0ba664f5adc0", "status_code": 200, "completed_at": "2026-02-25T11:57:15.809691979+08:00", "client_request_id": ""}
688	2026-02-25 11:57:15.831277+08	info	http.access	http request completed	8bce4b73-0cbf-4d67-8055-4546872eea70	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/subscriptions/active", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "8bce4b73-0cbf-4d67-8055-4546872eea70", "status_code": 200, "completed_at": "2026-02-25T11:57:15.831233356+08:00", "client_request_id": ""}
689	2026-02-25 11:57:15.831794+08	info	http.access	http request completed	bc026c87-b68e-41d5-ba7b-05a8b759ed95	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/dashboard/trend", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "bc026c87-b68e-41d5-ba7b-05a8b759ed95", "status_code": 200, "completed_at": "2026-02-25T11:57:15.831770153+08:00", "client_request_id": ""}
690	2026-02-25 11:57:15.832421+08	info	http.access	http request completed	1a2bcb89-cf35-4651-b73e-31384e0f8621	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/dashboard/models", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "1a2bcb89-cf35-4651-b73e-31384e0f8621", "status_code": 200, "completed_at": "2026-02-25T11:57:15.832404749+08:00", "client_request_id": ""}
691	2026-02-25 11:57:15.836347+08	info	http.access	http request completed	a0463898-b242-4510-9a4d-e9d0579c1113	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/dashboard/users-trend", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 4, "request_id": "a0463898-b242-4510-9a4d-e9d0579c1113", "status_code": 200, "completed_at": "2026-02-25T11:57:15.836311927+08:00", "client_request_id": ""}
692	2026-02-25 11:57:15.836667+08	info	http.access	http request completed	74ba275d-cb6d-4927-b8de-04ab0141bc22	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/dashboard/stats", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 8, "request_id": "74ba275d-cb6d-4927-b8de-04ab0141bc22", "status_code": 200, "completed_at": "2026-02-25T11:57:15.836646025+08:00", "client_request_id": ""}
693	2026-02-25 11:57:15.837305+08	info	http.access	http request completed	17adf3eb-0663-40b8-94a1-30aa33d3065c	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/announcements", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 9, "request_id": "17adf3eb-0663-40b8-94a1-30aa33d3065c", "status_code": 200, "completed_at": "2026-02-25T11:57:15.837285821+08:00", "client_request_id": ""}
694	2026-02-25 11:57:15.847671+08	info	http.access	http request completed	6d6b2e7c-06dc-4403-9f69-fd338b8ff7da	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/PlatformTypeBadge.vue_vue_type_script_setup_true_lang-88B5AzFJ.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "6d6b2e7c-06dc-4403-9f69-fd338b8ff7da", "status_code": 200, "completed_at": "2026-02-25T11:57:15.847656662+08:00", "client_request_id": ""}
695	2026-02-25 11:57:15.847956+08	info	http.access	http request completed	e780ff10-b606-4f23-9cd6-e06e8262422d	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/AccountsView-D1GA-FAQ.css", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "e780ff10-b606-4f23-9cd6-e06e8262422d", "status_code": 200, "completed_at": "2026-02-25T11:57:15.84794196+08:00", "client_request_id": ""}
696	2026-02-25 11:57:15.848073+08	info	http.access	http request completed	5a9b94af-a715-4843-b2e3-07d403b705f2	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/GroupSelector.vue_vue_type_script_setup_true_lang-CcNVQhCX.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 0, "request_id": "5a9b94af-a715-4843-b2e3-07d403b705f2", "status_code": 200, "completed_at": "2026-02-25T11:57:15.84804126+08:00", "client_request_id": ""}
697	2026-02-25 11:57:15.848935+08	info	http.access	http request completed	5641ceae-1eae-40b4-a978-261112bf2476	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/AccountsView-9-ehfXg1.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 1, "request_id": "5641ceae-1eae-40b4-a978-261112bf2476", "status_code": 200, "completed_at": "2026-02-25T11:57:15.848898655+08:00", "client_request_id": ""}
698	2026-02-25 11:57:15.849448+08	info	http.access	http request completed	a06ddcfe-b6d8-4cc0-a767-9ad3c34ea960	\N	\N	\N	\N	\N	{"env": "production", "path": "/assets/vendor-ui-CAt8eLho.js", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 1, "request_id": "a06ddcfe-b6d8-4cc0-a767-9ad3c34ea960", "status_code": 200, "completed_at": "2026-02-25T11:57:15.849424252+08:00", "client_request_id": ""}
699	2026-02-25 11:57:22.010173+08	info	http.access	http request completed	e3727f15-4c6a-479e-9f0b-c4cb46b43c0f	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/subscriptions/active", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "e3727f15-4c6a-479e-9f0b-c4cb46b43c0f", "status_code": 200, "completed_at": "2026-02-25T11:57:22.010160507+08:00", "client_request_id": ""}
700	2026-02-25 11:57:22.011087+08	info	http.access	http request completed	1b5c1a19-285b-48c6-8cba-cab3a91bddf2	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "1b5c1a19-285b-48c6-8cba-cab3a91bddf2", "status_code": 200, "completed_at": "2026-02-25T11:57:22.011077402+08:00", "client_request_id": ""}
701	2026-02-25 11:57:25.027436+08	info	http.access	http request completed	229e1684-bb3f-4ce7-a16b-fc1a332eb3ae	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/settings/stream-timeout", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "229e1684-bb3f-4ce7-a16b-fc1a332eb3ae", "status_code": 200, "completed_at": "2026-02-25T11:57:25.027421047+08:00", "client_request_id": ""}
702	2026-02-25 11:57:25.027428+08	info	http.access	http request completed	c79feb5f-30be-49df-a46f-ef83b6563542	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/settings/admin-api-key", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "c79feb5f-30be-49df-a46f-ef83b6563542", "status_code": 200, "completed_at": "2026-02-25T11:57:25.027405147+08:00", "client_request_id": ""}
703	2026-02-25 11:57:25.027939+08	info	http.access	http request completed	aad2493b-298d-4623-a4fc-0bd682b3aa5b	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/admin/settings", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "aad2493b-298d-4623-a4fc-0bd682b3aa5b", "status_code": 200, "completed_at": "2026-02-25T11:57:25.027924144+08:00", "client_request_id": ""}
704	2026-02-25 11:57:25.030947+08	info	http.access	http request completed	77278225-18b4-487f-8238-7fcc8de7524a	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/announcements", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 5, "request_id": "77278225-18b4-487f-8238-7fcc8de7524a", "status_code": 200, "completed_at": "2026-02-25T11:57:25.030922627+08:00", "client_request_id": ""}
705	2026-02-25 11:58:22.007533+08	info	http.access	http request completed	de9cec83-2de6-4997-8156-b46694ba6231	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "de9cec83-2de6-4997-8156-b46694ba6231", "status_code": 200, "completed_at": "2026-02-25T11:58:22.007516439+08:00", "client_request_id": ""}
706	2026-02-25 11:59:22.087542+08	info	http.access	http request completed	0d782875-7800-4a9a-b16b-afb819c9f109	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 4, "request_id": "0d782875-7800-4a9a-b16b-afb819c9f109", "status_code": 200, "completed_at": "2026-02-25T11:59:22.08744892+08:00", "client_request_id": ""}
709	2026-02-25 12:01:39.688943+08	error	service.pricing	[Pricing] Failed to compute local hash: open data/model_pricing.json: no such file or directory	\N	\N	\N	\N	\N	\N	{"env": "production", "service": "sub2api", "component": "service.pricing", "legacy_printf": true}
710	2026-02-25 12:01:40.302808+08	error	service.pricing	[Pricing] Failed to save file: open data/model_pricing.json: permission denied	\N	\N	\N	\N	\N	\N	{"env": "production", "service": "sub2api", "component": "service.pricing", "legacy_printf": true}
711	2026-02-25 12:01:40.305532+08	error	service.pricing	[Pricing] Failed to save hash: open data/model_pricing.sha256: permission denied	\N	\N	\N	\N	\N	\N	{"env": "production", "service": "sub2api", "component": "service.pricing", "legacy_printf": true}
712	2026-02-25 12:02:22.079575+08	info	http.access	http request completed	38151e19-5ac2-43a7-bd5a-9a363b62c4bc	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/subscriptions/active", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "38151e19-5ac2-43a7-bd5a-9a363b62c4bc", "status_code": 200, "completed_at": "2026-02-25T12:02:22.079559965+08:00", "client_request_id": ""}
713	2026-02-25 12:02:25.082848+08	info	http.access	http request completed	248259fb-ef93-4d2b-89a5-5862aa158e68	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "248259fb-ef93-4d2b-89a5-5862aa158e68", "status_code": 200, "completed_at": "2026-02-25T12:02:25.082833017+08:00", "client_request_id": ""}
720	2026-02-25 12:08:31.079474+08	info	http.access	http request completed	405d4d73-fd18-4b87-a136-99c8d14849a8	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "405d4d73-fd18-4b87-a136-99c8d14849a8", "status_code": 200, "completed_at": "2026-02-25T12:08:31.079461162+08:00", "client_request_id": ""}
707	2026-02-25 12:00:23.078968+08	info	http.access	http request completed	d4932305-a41c-40f7-be85-22d896ed1a5e	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 5, "request_id": "d4932305-a41c-40f7-be85-22d896ed1a5e", "status_code": 200, "completed_at": "2026-02-25T12:00:23.078937809+08:00", "client_request_id": ""}
708	2026-02-25 12:01:24.083168+08	info	http.access	http request completed	666a4bb8-faf3-4f0d-8a8f-5cf8e96c6fd3	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "666a4bb8-faf3-4f0d-8a8f-5cf8e96c6fd3", "status_code": 200, "completed_at": "2026-02-25T12:01:24.083154781+08:00", "client_request_id": ""}
714	2026-02-25 12:03:26.076605+08	info	http.access	http request completed	249ca04d-ff4a-48af-bac4-7b96285364cf	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "249ca04d-ff4a-48af-bac4-7b96285364cf", "status_code": 200, "completed_at": "2026-02-25T12:03:26.076585057+08:00", "client_request_id": ""}
717	2026-02-25 12:06:29.077133+08	info	http.access	http request completed	8efef3ed-56f8-41f9-bcf6-4789a1242f3c	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "8efef3ed-56f8-41f9-bcf6-4789a1242f3c", "status_code": 200, "completed_at": "2026-02-25T12:06:29.077116879+08:00", "client_request_id": ""}
716	2026-02-25 12:05:28.088067+08	info	http.access	http request completed	caa231c4-0d3c-41b6-ac1a-8675c10e78cb	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 2, "request_id": "caa231c4-0d3c-41b6-ac1a-8675c10e78cb", "status_code": 200, "completed_at": "2026-02-25T12:05:28.088051687+08:00", "client_request_id": ""}
718	2026-02-25 12:07:22.082571+08	info	http.access	http request completed	780d6919-fcc5-4260-b0f0-dac9ac0ab16c	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/subscriptions/active", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 4, "request_id": "780d6919-fcc5-4260-b0f0-dac9ac0ab16c", "status_code": 200, "completed_at": "2026-02-25T12:07:22.082555223+08:00", "client_request_id": ""}
719	2026-02-25 12:07:30.075573+08	info	http.access	http request completed	f35ea48e-bf45-44a0-85f2-0a64c212898b	\N	\N	\N	\N	\N	{"env": "production", "path": "/api/v1/auth/me", "method": "GET", "service": "sub2api", "protocol": "HTTP/1.1", "client_ip": "172.20.0.1", "component": "http.access", "latency_ms": 3, "request_id": "f35ea48e-bf45-44a0-85f2-0a64c212898b", "status_code": 200, "completed_at": "2026-02-25T12:07:30.075561614+08:00", "client_request_id": ""}
721	2026-02-25 12:11:39.68996+08	error	service.pricing	[Pricing] Failed to compute local hash: open data/model_pricing.json: no such file or directory	\N	\N	\N	\N	\N	\N	{"env": "production", "service": "sub2api", "component": "service.pricing", "legacy_printf": true}
722	2026-02-25 12:11:40.527815+08	error	service.pricing	[Pricing] Failed to save file: open data/model_pricing.json: permission denied	\N	\N	\N	\N	\N	\N	{"env": "production", "service": "sub2api", "component": "service.pricing", "legacy_printf": true}
723	2026-02-25 12:11:40.530509+08	error	service.pricing	[Pricing] Failed to save hash: open data/model_pricing.sha256: permission denied	\N	\N	\N	\N	\N	\N	{"env": "production", "service": "sub2api", "component": "service.pricing", "legacy_printf": true}
724	2026-02-25 12:21:39.689287+08	error	service.pricing	[Pricing] Failed to compute local hash: open data/model_pricing.json: no such file or directory	\N	\N	\N	\N	\N	\N	{"env": "production", "service": "sub2api", "component": "service.pricing", "legacy_printf": true}
725	2026-02-25 12:21:46.92274+08	error	service.pricing	[Pricing] Failed to save file: open data/model_pricing.json: permission denied	\N	\N	\N	\N	\N	\N	{"env": "production", "service": "sub2api", "component": "service.pricing", "legacy_printf": true}
726	2026-02-25 12:21:46.925487+08	error	service.pricing	[Pricing] Failed to save hash: open data/model_pricing.sha256: permission denied	\N	\N	\N	\N	\N	\N	{"env": "production", "service": "sub2api", "component": "service.pricing", "legacy_printf": true}
727	2026-02-25 12:31:39.689441+08	error	service.pricing	[Pricing] Failed to compute local hash: open data/model_pricing.json: no such file or directory	\N	\N	\N	\N	\N	\N	{"env": "production", "service": "sub2api", "component": "service.pricing", "legacy_printf": true}
728	2026-02-25 12:31:46.383171+08	error	service.pricing	[Pricing] Failed to save file: open data/model_pricing.json: permission denied	\N	\N	\N	\N	\N	\N	{"env": "production", "service": "sub2api", "component": "service.pricing", "legacy_printf": true}
729	2026-02-25 12:31:46.385894+08	error	service.pricing	[Pricing] Failed to save hash: open data/model_pricing.sha256: permission denied	\N	\N	\N	\N	\N	\N	{"env": "production", "service": "sub2api", "component": "service.pricing", "legacy_printf": true}
730	2026-02-25 12:41:39.689337+08	error	service.pricing	[Pricing] Failed to compute local hash: open data/model_pricing.json: no such file or directory	\N	\N	\N	\N	\N	\N	{"env": "production", "service": "sub2api", "component": "service.pricing", "legacy_printf": true}
731	2026-02-25 12:41:49.690375+08	error	service.pricing	[Pricing] Sync failed: fetch remote hash: Get "https://raw.githubusercontent.com/Wei-Shaw/claude-relay-service/price-mirror/model_prices_and_context_window.sha256": context deadline exceeded	\N	\N	\N	\N	\N	\N	{"env": "production", "service": "sub2api", "component": "service.pricing", "legacy_printf": true}
732	2026-02-25 12:51:39.689201+08	error	service.pricing	[Pricing] Failed to compute local hash: open data/model_pricing.json: no such file or directory	\N	\N	\N	\N	\N	\N	{"env": "production", "service": "sub2api", "component": "service.pricing", "legacy_printf": true}
733	2026-02-25 12:51:40.412537+08	error	service.pricing	[Pricing] Failed to save file: open data/model_pricing.json: permission denied	\N	\N	\N	\N	\N	\N	{"env": "production", "service": "sub2api", "component": "service.pricing", "legacy_printf": true}
734	2026-02-25 12:51:40.415522+08	error	service.pricing	[Pricing] Failed to save hash: open data/model_pricing.sha256: permission denied	\N	\N	\N	\N	\N	\N	{"env": "production", "service": "sub2api", "component": "service.pricing", "legacy_printf": true}
735	2026-02-25 13:01:39.689667+08	error	service.pricing	[Pricing] Failed to compute local hash: open data/model_pricing.json: no such file or directory	\N	\N	\N	\N	\N	\N	{"env": "production", "service": "sub2api", "component": "service.pricing", "legacy_printf": true}
736	2026-02-25 13:01:49.690622+08	error	service.pricing	[Pricing] Sync failed: fetch remote hash: Get "https://raw.githubusercontent.com/Wei-Shaw/claude-relay-service/price-mirror/model_prices_and_context_window.sha256": context deadline exceeded	\N	\N	\N	\N	\N	\N	{"env": "production", "service": "sub2api", "component": "service.pricing", "legacy_printf": true}
737	2026-02-25 13:11:39.688992+08	error	service.pricing	[Pricing] Failed to compute local hash: open data/model_pricing.json: no such file or directory	\N	\N	\N	\N	\N	\N	{"env": "production", "service": "sub2api", "component": "service.pricing", "legacy_printf": true}
738	2026-02-25 13:11:42.690778+08	error	service.pricing	[Pricing] Failed to save file: open data/model_pricing.json: permission denied	\N	\N	\N	\N	\N	\N	{"env": "production", "service": "sub2api", "component": "service.pricing", "legacy_printf": true}
739	2026-02-25 13:11:42.693497+08	error	service.pricing	[Pricing] Failed to save hash: open data/model_pricing.sha256: permission denied	\N	\N	\N	\N	\N	\N	{"env": "production", "service": "sub2api", "component": "service.pricing", "legacy_printf": true}
740	2026-02-25 13:21:39.689333+08	error	service.pricing	[Pricing] Failed to compute local hash: open data/model_pricing.json: no such file or directory	\N	\N	\N	\N	\N	\N	{"env": "production", "service": "sub2api", "component": "service.pricing", "legacy_printf": true}
741	2026-02-25 13:21:40.736478+08	error	service.pricing	[Pricing] Failed to save file: open data/model_pricing.json: permission denied	\N	\N	\N	\N	\N	\N	{"env": "production", "service": "sub2api", "component": "service.pricing", "legacy_printf": true}
742	2026-02-25 13:21:40.739195+08	error	service.pricing	[Pricing] Failed to save hash: open data/model_pricing.sha256: permission denied	\N	\N	\N	\N	\N	\N	{"env": "production", "service": "sub2api", "component": "service.pricing", "legacy_printf": true}
743	2026-02-25 13:31:39.689538+08	error	service.pricing	[Pricing] Failed to compute local hash: open data/model_pricing.json: no such file or directory	\N	\N	\N	\N	\N	\N	{"env": "production", "service": "sub2api", "component": "service.pricing", "legacy_printf": true}
744	2026-02-25 13:31:41.587156+08	error	service.pricing	[Pricing] Failed to save file: open data/model_pricing.json: permission denied	\N	\N	\N	\N	\N	\N	{"env": "production", "service": "sub2api", "component": "service.pricing", "legacy_printf": true}
\.


--
-- Data for Name: ops_system_metrics; Type: TABLE DATA; Schema: public; Owner: sub2api
--

COPY public.ops_system_metrics (id, created_at, window_minutes, platform, group_id, success_count, error_count_total, business_limited_count, error_count_sla, upstream_error_count_excl_429_529, upstream_429_count, upstream_529_count, token_consumed, qps, tps, duration_p50_ms, duration_p90_ms, duration_p95_ms, duration_p99_ms, duration_avg_ms, duration_max_ms, ttft_p50_ms, ttft_p90_ms, ttft_p95_ms, ttft_p99_ms, ttft_avg_ms, ttft_max_ms, cpu_usage_percent, memory_used_mb, memory_total_mb, memory_usage_percent, db_ok, redis_ok, db_conn_active, db_conn_idle, db_conn_waiting, goroutine_count, concurrency_queue_depth, redis_conn_total, redis_conn_idle, account_switch_count) FROM stdin;
1	2026-02-25 10:51:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	5.4	31	7796	0.4	t	t	4	5	\N	61	\N	259	259	0
2	2026-02-25 10:52:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.2	34	7796	0.4	t	t	\N	9	\N	65	\N	259	259	0
3	2026-02-25 10:53:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.9	41	7796	0.5	t	t	\N	9	\N	64	\N	259	259	0
4	2026-02-25 10:54:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.9	41	7796	0.5	t	t	\N	9	\N	64	\N	259	259	0
5	2026-02-25 10:55:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	36	7796	0.5	t	t	\N	9	\N	59	\N	259	259	0
6	2026-02-25 10:56:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	32	7796	0.4	t	t	\N	9	\N	59	\N	259	259	0
7	2026-02-25 10:57:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	31	7796	0.4	t	t	\N	6	\N	59	\N	259	259	0
8	2026-02-25 10:58:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.9	31	7796	0.4	t	t	\N	5	\N	60	\N	259	259	0
9	2026-02-25 10:59:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.9	32	7796	0.4	t	t	\N	5	\N	63	\N	259	259	0
10	2026-02-25 11:00:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	31	7796	0.4	t	t	\N	5	\N	63	\N	259	259	0
11	2026-02-25 11:01:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.3	38	7796	0.5	t	t	\N	5	\N	62	\N	259	259	0
12	2026-02-25 11:02:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	25.3	38	7796	0.5	t	t	\N	5	\N	60	\N	259	259	0
13	2026-02-25 11:02:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.3	28	7796	0.4	t	t	7	2	\N	63	\N	259	259	0
14	2026-02-25 11:03:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.2	32	7796	0.4	t	t	\N	9	\N	64	\N	259	259	0
15	2026-02-25 11:04:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	26.3	34	7796	0.4	t	t	\N	9	\N	63	\N	259	259	0
16	2026-02-25 11:05:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	7.8	34	7796	0.4	t	t	7	2	\N	65	\N	259	259	0
17	2026-02-25 11:06:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1	38	7796	0.5	t	t	\N	9	\N	65	\N	259	259	0
18	2026-02-25 11:07:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1	38	7796	0.5	t	t	\N	9	\N	64	\N	259	259	0
19	2026-02-25 11:08:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.2	36	7796	0.5	t	t	\N	9	\N	64	\N	259	259	0
20	2026-02-25 11:09:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.5	36	7796	0.5	t	t	\N	9	\N	62	\N	259	259	0
21	2026-02-25 11:10:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.9	29	7796	0.4	t	t	\N	8	\N	59	\N	259	259	0
22	2026-02-25 11:11:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	4.6	29	7796	0.4	t	t	\N	5	\N	59	\N	259	259	0
23	2026-02-25 11:12:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.7	29	7796	0.4	t	t	\N	5	\N	58	\N	259	259	0
24	2026-02-25 11:13:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	37.5	35	7796	0.4	t	t	\N	5	\N	59	\N	259	259	0
25	2026-02-25 11:13:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	4.5	36	7796	0.5	t	t	7	2	\N	63	\N	259	259	0
26	2026-02-25 11:14:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.1	37	7796	0.5	t	t	\N	9	\N	65	\N	259	259	0
27	2026-02-25 11:15:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.1	37	7796	0.5	t	t	\N	9	\N	64	\N	259	259	0
28	2026-02-25 11:16:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1	36	7796	0.5	t	t	\N	9	\N	59	\N	259	259	0
29	2026-02-25 11:17:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.9	34	7796	0.4	t	t	\N	9	\N	63	\N	259	259	0
30	2026-02-25 11:18:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.9	31	7796	0.4	t	t	\N	9	\N	63	\N	259	259	0
31	2026-02-25 11:19:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.9	31	7796	0.4	t	t	\N	5	\N	63	\N	259	259	0
32	2026-02-25 11:20:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.9	31	7796	0.4	t	t	\N	5	\N	63	\N	259	259	0
33	2026-02-25 11:21:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.6	32	7796	0.4	t	t	\N	5	\N	63	\N	259	259	0
34	2026-02-25 11:22:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	32	7796	0.4	t	t	\N	5	\N	59	\N	259	259	0
35	2026-02-25 11:23:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	2.4	30	7796	0.4	t	t	1	4	\N	62	\N	259	259	0
36	2026-02-25 11:24:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	2.4	35	7796	0.4	t	t	\N	5	\N	60	\N	259	259	0
37	2026-02-25 11:25:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.2	37	7796	0.5	t	t	\N	5	\N	60	\N	259	259	0
38	2026-02-25 11:26:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	36	7796	0.5	t	t	\N	5	\N	60	\N	259	259	0
39	2026-02-25 11:27:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.4	37	7796	0.5	t	t	\N	5	\N	59	\N	259	259	0
40	2026-02-25 11:28:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.9	30	7796	0.4	t	t	\N	5	\N	59	\N	259	259	0
41	2026-02-25 11:29:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.2	30	7796	0.4	t	t	\N	5	\N	59	\N	259	259	0
42	2026-02-25 11:30:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	30	7796	0.4	t	t	\N	5	\N	58	\N	259	259	0
43	2026-02-25 11:31:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	3.3	29	7796	0.4	t	t	\N	5	\N	58	\N	259	259	0
44	2026-02-25 11:32:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	2.3	30	7796	0.4	t	t	\N	5	\N	58	\N	259	259	0
50	2026-02-25 11:38:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.6	30	7796	0.4	t	t	\N	5	\N	58	\N	259	259	0
45	2026-02-25 11:33:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.9	31	7796	0.4	t	t	\N	5	\N	60	\N	259	259	0
47	2026-02-25 11:35:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	37	7796	0.5	t	t	\N	5	\N	58	\N	259	259	0
48	2026-02-25 11:36:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.4	37	7796	0.5	t	t	\N	5	\N	58	\N	259	259	0
46	2026-02-25 11:34:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.2	36	7796	0.5	t	t	\N	5	\N	59	\N	259	259	0
51	2026-02-25 11:39:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	30	7796	0.4	t	t	\N	5	\N	58	\N	259	259	0
49	2026-02-25 11:37:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	37	7796	0.5	t	t	\N	5	\N	58	\N	259	259	0
52	2026-02-25 11:40:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.4	30	7796	0.4	t	t	\N	5	\N	58	\N	259	259	0
53	2026-02-25 11:41:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.1	30	7796	0.4	t	t	\N	5	\N	58	\N	259	259	0
54	2026-02-25 11:42:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.3	30	7796	0.4	t	t	\N	5	\N	58	\N	259	259	0
55	2026-02-25 11:43:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	30	7796	0.4	t	t	\N	5	\N	60	\N	259	259	0
56	2026-02-25 11:44:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	36	7796	0.5	t	t	\N	4	\N	59	\N	259	259	0
57	2026-02-25 11:45:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	37	7796	0.5	t	t	\N	4	\N	58	\N	259	259	0
58	2026-02-25 11:46:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.5	36	7796	0.5	t	t	\N	4	\N	58	\N	259	259	0
59	2026-02-25 11:47:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.6	37	7796	0.5	t	t	\N	4	\N	58	\N	259	259	0
60	2026-02-25 11:48:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	30	7796	0.4	t	t	\N	5	\N	58	\N	259	259	0
61	2026-02-25 11:49:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	33	7796	0.4	t	t	\N	7	\N	64	\N	259	259	0
62	2026-02-25 11:50:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	6.7	33	7796	0.4	t	t	\N	7	\N	64	\N	259	259	0
63	2026-02-25 11:51:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	32.8	37	7796	0.5	t	t	\N	7	\N	59	\N	259	259	0
64	2026-02-25 11:51:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	9.3	28	7796	0.4	t	t	7	2	\N	62	\N	259	259	0
65	2026-02-25 11:52:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.9	41	7796	0.5	t	t	\N	9	\N	71	\N	259	259	0
66	2026-02-25 11:53:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	40	7796	0.5	t	t	\N	9	\N	64	\N	259	259	0
67	2026-02-25 11:54:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.2	31	7796	0.4	t	t	\N	9	\N	59	\N	259	259	0
68	2026-02-25 11:55:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.4	31	7796	0.4	t	t	\N	9	\N	59	\N	259	259	0
69	2026-02-25 11:56:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.4	30	7796	0.4	t	t	\N	8	\N	63	\N	259	259	0
70	2026-02-25 11:57:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.5	30	7796	0.4	t	t	\N	5	\N	64	\N	259	259	0
71	2026-02-25 11:58:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.5	30	7796	0.4	t	t	\N	5	\N	64	\N	259	259	0
72	2026-02-25 11:59:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.5	30	7796	0.4	t	t	1	4	\N	59	\N	259	259	0
73	2026-02-25 12:00:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.4	29	7796	0.4	t	t	\N	5	\N	59	\N	259	259	0
74	2026-02-25 12:01:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.4	29	7796	0.4	t	t	1	4	\N	62	\N	259	259	0
75	2026-02-25 12:02:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.4	36	7796	0.5	t	t	\N	5	\N	60	\N	259	259	0
76	2026-02-25 12:03:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.4	36	7796	0.5	t	t	\N	5	\N	59	\N	259	259	0
77	2026-02-25 12:04:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.5	29	7796	0.4	t	t	\N	5	\N	59	\N	259	259	0
78	2026-02-25 12:05:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.3	29	7796	0.4	t	t	\N	5	\N	59	\N	259	259	0
79	2026-02-25 12:06:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.4	29	7796	0.4	t	t	\N	5	\N	59	\N	259	259	0
80	2026-02-25 12:07:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.3	29	7796	0.4	t	t	\N	5	\N	59	\N	259	259	0
81	2026-02-25 12:08:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.3	29	7796	0.4	t	t	\N	5	\N	59	\N	259	259	0
82	2026-02-25 12:09:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.5	29	7796	0.4	t	t	\N	5	\N	59	\N	259	259	0
83	2026-02-25 12:10:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.4	29	7796	0.4	t	t	\N	5	\N	58	\N	259	259	0
84	2026-02-25 12:11:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.5	29	7796	0.4	t	t	\N	5	\N	60	\N	259	259	0
85	2026-02-25 12:12:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.4	35	7796	0.4	t	t	\N	5	\N	59	\N	259	259	0
86	2026-02-25 12:13:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.4	35	7796	0.4	t	t	\N	5	\N	58	\N	259	259	0
87	2026-02-25 12:14:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.4	29	7796	0.4	t	t	\N	5	\N	58	\N	259	259	0
88	2026-02-25 12:15:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.4	28	7796	0.4	t	t	\N	5	\N	58	\N	259	259	0
89	2026-02-25 12:16:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.4	29	7796	0.4	t	t	\N	5	\N	58	\N	259	259	0
90	2026-02-25 12:17:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.4	29	7796	0.4	t	t	\N	5	\N	58	\N	259	259	0
91	2026-02-25 12:18:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.4	28	7796	0.4	t	t	\N	5	\N	58	\N	259	259	0
92	2026-02-25 12:19:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.4	29	7796	0.4	t	t	\N	5	\N	58	\N	259	259	0
98	2026-02-25 12:25:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.4	28	7796	0.4	t	t	\N	4	\N	58	\N	259	259	0
102	2026-02-25 12:29:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.3	28	7796	0.4	t	t	\N	5	\N	58	\N	259	259	0
93	2026-02-25 12:20:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.3	29	7796	0.4	t	t	\N	5	\N	58	\N	259	259	0
94	2026-02-25 12:21:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.4	29	7796	0.4	t	t	\N	5	\N	61	\N	259	259	0
95	2026-02-25 12:22:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.4	35	7796	0.4	t	t	\N	4	\N	59	\N	259	259	0
96	2026-02-25 12:23:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.4	35	7796	0.4	t	t	\N	4	\N	58	\N	259	259	0
97	2026-02-25 12:24:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.3	28	7796	0.4	t	t	\N	4	\N	58	\N	259	259	0
99	2026-02-25 12:26:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.3	28	7796	0.4	t	t	\N	5	\N	58	\N	259	259	0
100	2026-02-25 12:27:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.4	28	7796	0.4	t	t	\N	5	\N	58	\N	259	259	0
101	2026-02-25 12:28:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.4	29	7796	0.4	t	t	\N	5	\N	58	\N	259	259	0
103	2026-02-25 12:30:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.4	29	7796	0.4	t	t	\N	5	\N	58	\N	259	259	0
104	2026-02-25 12:31:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.4	28	7796	0.4	t	t	\N	5	\N	61	\N	259	259	0
105	2026-02-25 12:32:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.4	35	7796	0.4	t	t	\N	5	\N	59	\N	259	259	0
106	2026-02-25 12:33:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.3	35	7796	0.4	t	t	\N	5	\N	58	\N	259	259	0
107	2026-02-25 12:34:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.4	28	7796	0.4	t	t	\N	5	\N	58	\N	259	259	0
108	2026-02-25 12:35:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.4	28	7796	0.4	t	t	\N	5	\N	58	\N	259	259	0
109	2026-02-25 12:36:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.3	28	7796	0.4	t	t	\N	5	\N	58	\N	259	259	0
110	2026-02-25 12:37:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.4	28	7796	0.4	t	t	\N	5	\N	58	\N	259	259	0
111	2026-02-25 12:38:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.4	28	7796	0.4	t	t	\N	5	\N	58	\N	259	259	0
112	2026-02-25 12:39:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.3	28	7796	0.4	t	t	\N	5	\N	58	\N	259	259	0
113	2026-02-25 12:40:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.3	28	7796	0.4	t	t	\N	5	\N	58	\N	259	259	0
114	2026-02-25 12:41:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.3	28	7796	0.4	t	t	\N	5	\N	60	\N	259	259	0
115	2026-02-25 12:42:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.4	28	7796	0.4	t	t	\N	5	\N	59	\N	259	259	0
116	2026-02-25 12:43:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.4	28	7796	0.4	t	t	\N	5	\N	58	\N	259	259	0
117	2026-02-25 12:44:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.5	28	7796	0.4	t	t	\N	5	\N	58	\N	259	259	0
118	2026-02-25 12:45:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.4	28	7796	0.4	t	t	\N	5	\N	58	\N	259	259	0
119	2026-02-25 12:46:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	28	7796	0.4	t	t	\N	5	\N	58	\N	259	259	0
120	2026-02-25 12:47:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	28	7796	0.4	t	t	\N	5	\N	58	\N	259	259	0
121	2026-02-25 12:48:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	28	7796	0.4	t	t	\N	5	\N	58	\N	259	259	0
122	2026-02-25 12:49:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	28	7796	0.4	t	t	\N	5	\N	58	\N	259	259	0
123	2026-02-25 12:50:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	28	7796	0.4	t	t	\N	5	\N	58	\N	259	259	0
124	2026-02-25 12:51:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	35	7796	0.4	t	t	\N	3	\N	59	\N	259	259	0
125	2026-02-25 12:52:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.1	35	7796	0.4	t	t	\N	4	\N	59	\N	259	259	0
126	2026-02-25 12:53:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	42	7796	0.5	t	t	\N	4	\N	58	\N	259	259	0
127	2026-02-25 12:54:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	35	7796	0.4	t	t	\N	4	\N	58	\N	259	259	0
128	2026-02-25 12:55:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	35	7796	0.4	t	t	\N	4	\N	58	\N	259	259	0
129	2026-02-25 12:56:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	35	7796	0.4	t	t	\N	4	\N	58	\N	259	259	0
130	2026-02-25 12:57:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	34	7796	0.4	t	t	\N	4	\N	58	\N	259	259	0
131	2026-02-25 12:58:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	35	7796	0.4	t	t	\N	4	\N	58	\N	259	259	0
132	2026-02-25 12:59:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	35	7796	0.4	t	t	\N	4	\N	58	\N	259	259	0
133	2026-02-25 13:00:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	35	7796	0.4	t	t	\N	4	\N	58	\N	259	259	0
134	2026-02-25 13:01:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	35	7796	0.4	t	t	\N	5	\N	60	\N	259	259	0
135	2026-02-25 13:02:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.7	35	7796	0.4	t	t	\N	5	\N	59	\N	259	259	0
138	2026-02-25 13:05:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	35	7796	0.4	t	t	\N	5	\N	58	\N	259	259	0
142	2026-02-25 13:09:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	35	7796	0.4	t	t	\N	4	\N	58	\N	259	259	0
143	2026-02-25 13:10:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	35	7796	0.4	t	t	\N	4	\N	58	\N	259	259	0
148	2026-02-25 13:15:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	35	7796	0.4	t	t	\N	5	\N	58	\N	259	259	0
151	2026-02-25 13:18:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	35	7796	0.4	t	t	\N	5	\N	58	\N	259	259	0
152	2026-02-25 13:19:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	35	7796	0.4	t	t	\N	5	\N	58	\N	259	259	0
153	2026-02-25 13:20:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	35	7796	0.4	t	t	\N	5	\N	58	\N	259	259	0
136	2026-02-25 13:03:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	35	7796	0.4	t	t	\N	5	\N	58	\N	259	259	0
139	2026-02-25 13:06:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.7	35	7796	0.4	t	t	\N	5	\N	58	\N	259	259	0
140	2026-02-25 13:07:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	35	7796	0.4	t	t	\N	4	\N	58	\N	259	259	0
147	2026-02-25 13:14:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	35	7796	0.4	t	t	\N	5	\N	58	\N	259	259	0
157	2026-02-25 13:24:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	35	7796	0.4	t	t	\N	4	\N	58	\N	259	259	0
163	2026-02-25 13:30:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	35	7796	0.4	t	t	\N	4	\N	58	\N	259	259	0
137	2026-02-25 13:04:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	35	7796	0.4	t	t	\N	5	\N	58	\N	259	259	0
141	2026-02-25 13:08:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	35	7796	0.4	t	t	\N	4	\N	58	\N	259	259	0
144	2026-02-25 13:11:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	35	7796	0.4	t	t	\N	5	\N	61	\N	259	259	0
145	2026-02-25 13:12:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	42	7796	0.5	t	t	\N	5	\N	59	\N	259	259	0
146	2026-02-25 13:13:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	42	7796	0.5	t	t	\N	5	\N	58	\N	259	259	0
149	2026-02-25 13:16:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	35	7796	0.4	t	t	\N	5	\N	58	\N	259	259	0
150	2026-02-25 13:17:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	35	7796	0.4	t	t	\N	5	\N	58	\N	259	259	0
155	2026-02-25 13:22:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	42	7796	0.5	t	t	\N	3	\N	59	\N	259	259	0
162	2026-02-25 13:29:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	35	7796	0.4	t	t	\N	4	\N	58	\N	259	259	0
154	2026-02-25 13:21:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	41	7796	0.5	t	t	\N	4	\N	59	\N	259	259	0
156	2026-02-25 13:23:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	41	7796	0.5	t	t	\N	4	\N	58	\N	259	259	0
158	2026-02-25 13:25:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	35	7796	0.4	t	t	\N	4	\N	58	\N	259	259	0
159	2026-02-25 13:26:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	35	7796	0.4	t	t	\N	4	\N	58	\N	259	259	0
160	2026-02-25 13:27:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	35	7796	0.4	t	t	\N	4	\N	58	\N	259	259	0
161	2026-02-25 13:28:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	35	7796	0.4	t	t	\N	4	\N	58	\N	259	259	0
164	2026-02-25 13:31:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	35	7796	0.4	t	t	\N	4	\N	60	\N	259	259	0
165	2026-02-25 13:32:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	42	7796	0.5	t	t	\N	4	\N	59	\N	259	259	0
166	2026-02-25 13:33:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	0.8	42	7796	0.5	t	t	\N	4	\N	58	\N	259	259	0
167	2026-02-25 13:34:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1	35	7796	0.4	t	t	\N	4	\N	58	\N	259	259	0
168	2026-02-25 13:35:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	22.9	35	7796	0.4	t	t	\N	5	\N	58	\N	259	259	0
169	2026-02-25 13:36:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	2.1	35	7796	0.4	t	t	\N	5	\N	58	\N	259	259	0
170	2026-02-25 13:37:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	2.1	35	7796	0.4	t	t	\N	5	\N	58	\N	259	259	0
171	2026-02-25 13:38:00+08	1	\N	\N	0	0	0	0	0	0	0	0	0	0	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	1.9	35	7796	0.4	t	t	\N	5	\N	58	\N	259	259	0
\.


--
-- Data for Name: orphan_allowed_groups_audit; Type: TABLE DATA; Schema: public; Owner: sub2api
--

COPY public.orphan_allowed_groups_audit (id, user_id, group_id, recorded_at) FROM stdin;
\.


--
-- Data for Name: promo_code_usages; Type: TABLE DATA; Schema: public; Owner: sub2api
--

COPY public.promo_code_usages (id, promo_code_id, user_id, bonus_amount, used_at) FROM stdin;
\.


--
-- Data for Name: promo_codes; Type: TABLE DATA; Schema: public; Owner: sub2api
--

COPY public.promo_codes (id, code, bonus_amount, max_uses, used_count, status, expires_at, notes, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: proxies; Type: TABLE DATA; Schema: public; Owner: sub2api
--

COPY public.proxies (id, name, protocol, host, port, username, password, status, created_at, updated_at, deleted_at) FROM stdin;
\.


--
-- Data for Name: redeem_codes; Type: TABLE DATA; Schema: public; Owner: sub2api
--

COPY public.redeem_codes (id, code, type, value, status, used_by, used_at, created_at, notes, group_id, validity_days) FROM stdin;
\.


--
-- Data for Name: scheduler_outbox; Type: TABLE DATA; Schema: public; Owner: sub2api
--

COPY public.scheduler_outbox (id, event_type, account_id, group_id, payload, created_at) FROM stdin;
\.


--
-- Data for Name: schema_migrations; Type: TABLE DATA; Schema: public; Owner: sub2api
--

COPY public.schema_migrations (filename, checksum, applied_at) FROM stdin;
001_init.sql	9ba0369779484625edcea7a7d1d4582397e31546db9149b05004990a3f16c630	2026-02-25 10:51:17.935946+08
002_account_type_migration.sql	aad3816e44f58ff007ea4df8092aae580f3f85180314c1deb1b1054b20892bbf	2026-02-25 10:51:18.014817+08
003_subscription.sql	4642fcb1ccd7954b1d3eef8f795cfba2ce21431257346cc5a7568cde61a60b13	2026-02-25 10:51:18.023065+08
004_add_redeem_code_notes.sql	fb171d084795906ce8e388eec34133dfa256e1ecb1621083f12aa47c6368bfd8	2026-02-25 10:51:18.052142+08
005_schema_parity.sql	2ae9e9ff98adb2a684aeb4d839be7ee00e7a26af167460f886133ac55361b5bf	2026-02-25 10:51:18.058557+08
006_add_users_allowed_groups_compat.sql	900f5ba934e8d66bba7d94f1d34463a9022e0e72c3ce911260d7c703449a33ae	2026-02-25 10:51:18.084998+08
006_fix_invalid_subscription_expires_at.sql	ed5d6553a86578d987088331bc8810808b75e554a160b66ff4626815ea838354	2026-02-25 10:51:18.092239+08
006b_guard_users_allowed_groups.sql	6953b71b92d0ed2f035137fdc4e4fb6cc056861b22e28c5612950c08cedf564e	2026-02-25 10:51:18.09924+08
007_add_user_allowed_groups.sql	76694d87e70be4fa9d9f27cd308717685a426d9a64ded36a5a9517956ebec972	2026-02-25 10:51:18.111439+08
008_seed_default_group.sql	f4bd452fb097a509120399b6121abb17d1a212330185b40f1e5ec69c6e16954a	2026-02-25 10:51:18.123449+08
009_fix_usage_logs_cache_columns.sql	9a3c22b296ea5a628eb8b35b34318f035b9ac177dfc7d1db26b0901dcd98bafb	2026-02-25 10:51:18.128832+08
010_add_usage_logs_aggregated_indexes.sql	3537ff30a25b71c93458f77e08ce5b60355e0a3068bfd49e2d9bdb6e6deee027	2026-02-25 10:51:18.139597+08
011_remove_duplicate_unique_indexes.sql	ae4c6f5bab86f399ad812b7ffc927402c0a8decef85bf7c3d7a8877863ba520e	2026-02-25 10:51:18.147044+08
012_add_user_subscription_soft_delete.sql	5c829927c7f882fbe0258239c3673f865b03dfc3ee274674d7a2cedb06deaf24	2026-02-25 10:51:18.153726+08
013_log_orphan_allowed_groups.sql	4f2d8e9078f02de763977963f711ed2e82587b9ac72947c1b8019594b49d6dd8	2026-02-25 10:51:18.159538+08
014_drop_legacy_allowed_groups.sql	b63fc37ba6a6ffdcb50e082250be5f34f40632597d568bb97247c607198befcc	2026-02-25 10:51:18.168653+08
015_fix_settings_unique_constraint.sql	b6f7f2244cb66fa5a5b088a1f40d2694b95e23fce971bc2562bcbe306efe48d3	2026-02-25 10:51:18.17309+08
016_soft_delete_partial_unique_indexes.sql	213c9358247ca0072d9c6a441eb7e1df9513e7e8040e6ca4f0d616c319f588ba	2026-02-25 10:51:18.177233+08
018_user_attributes.sql	af99c63b62dcd029b52b2693281e0dea4dfc751dadefd4cbbc894359f2cc8014	2026-02-25 10:51:18.186635+08
019_migrate_wechat_to_attributes.sql	d45e05b4bb722b287377790583c2677b8666dbf7e02b626c93468491d4ce8cf8	2026-02-25 10:51:18.205475+08
020_add_temp_unschedulable.sql	0ffee69180cdb20aba0116dc2c20da781bbe9bd2418d41f30880bbf12f51efbe	2026-02-25 10:51:18.217025+08
024_add_gemini_tier_id.sql	b54de1b9a4423224f7aef5e644d1af115214d58dd61befd3c25db3e709b9163a	2026-02-25 10:51:18.222499+08
026_ops_metrics_aggregation_tables.sql	cff5e8fe80d8f8fd94cf6d9f2b01065f9b3ebdff8a99f941b927d530a418ba62	2026-02-25 10:51:18.227989+08
027_usage_billing_consistency.sql	68df49831cadfb2c5d1f8e24b8b36068be454cca9fdf6df1141593ee20c98dd8	2026-02-25 10:51:18.240374+08
028_add_account_notes.sql	8d52c15e184ffe112185eeaea5bad35afe3761dfb7cc9e9b1644445134420300	2026-02-25 10:51:18.255395+08
028_add_usage_logs_user_agent.sql	024d6dd42321b3c0f35cf8e15766e1dda993c08c1d69878e8888d6cb4bccde2d	2026-02-25 10:51:18.261009+08
028_group_image_pricing.sql	e1276ed19c083a32eb62272abc9a9640e3aca1dc0cee8fc661de873959421d80	2026-02-25 10:51:18.267707+08
029_add_group_claude_code_restriction.sql	f0c5bb461d29a64410ed05a3f2dd478cf42deddbf1013e23f9468c573455f1be	2026-02-25 10:51:18.273783+08
029_usage_log_image_fields.sql	ce14c36d169e6d6d070069d11f35a8622298436c204a54a0ae580f0e63396a4f	2026-02-25 10:51:18.2812+08
030_add_account_expires_at.sql	d6ea81863b7d7031426009ed081ce76b14325664aa1782dd496a527ca0dab85b	2026-02-25 10:51:18.287116+08
031_add_ip_address.sql	c9ce8db0e582b1a844e8529bb0cf3bd6ccf5bf6fa0949bb4955a963801a97da0	2026-02-25 10:51:18.296107+08
032_add_api_key_ip_restriction.sql	e0f084b7533d53faee48f122a04ef3988625e61c6356448a07085236d8c96122	2026-02-25 10:51:18.302502+08
033_add_promo_codes.sql	913c0f2a90943c51aa0134cf7f4339dfdafad8b5e14738159a1841f14b4f8ff9	2026-02-25 10:51:18.308221+08
033_ops_monitoring_vnext.sql	accf363544d187aecad4f1c68fe34118f86d1a931465e66490c530d3f3f1106d	2026-02-25 10:51:18.327435+08
034_ops_upstream_error_events.sql	1b2e69d10195f0264b034873e0a9d96bb946072886aad9f63307c08808689a56	2026-02-25 10:51:18.413017+08
034_usage_dashboard_aggregation_tables.sql	20bf67f62858c3c292c66ea667e9ac7d5c7b645077e6413a03700be1b480d962	2026-02-25 10:51:18.418635+08
035_usage_logs_partitioning.sql	91a02804ee4292e1dc33cda28335725b1011236bb19f577d2c8e6b4bcbffd3ba	2026-02-25 10:51:18.438026+08
036_ops_error_logs_add_is_count_tokens.sql	ed9ee240c43ef259f18a7ca440d73f285988d2aa57af229e0b69344f11af3bf4	2026-02-25 10:51:18.443408+08
036_scheduler_outbox.sql	e88635e14a2b9f04041495890c3d98125bae119ecf3936c070d82e017ee2a4c0	2026-02-25 10:51:18.448748+08
037_add_account_rate_multiplier.sql	e8a2bea65eac919a323738098402bb6ea53720cbe1111a6cec823d2d36ebfd20	2026-02-25 10:51:18.457943+08
037_ops_alert_silences.sql	72143a1ce3528ebc47472759c59011ec6993b25a3f22d50485538710047438c6	2026-02-25 10:51:18.464315+08
038_ops_errors_resolution_retry_results_and_standardize_classification.sql	4cc121d97c7f59e9def9397b7d0314d4dfbfe4cd831698359456dd49bf995ece	2026-02-25 10:51:18.47549+08
039_ops_job_heartbeats_add_last_result.sql	5dad52cd5a61ad98029ba2de4ea3903cbc9c40a43731dd8a3f8a8129277ec47b	2026-02-25 10:51:18.488975+08
040_add_group_model_routing.sql	fb8727cfea19997101646457a3c31c3efc647e3cb2b8a0e04d06a24c3a608862	2026-02-25 10:51:18.493676+08
041_add_model_routing_enabled.sql	5cee91bdfc5afe4815dba6b127755a76d33ab55a93419c5b51e57d8dfd9cba3a	2026-02-25 10:51:18.499841+08
042_add_usage_cleanup_tasks.sql	19788b90712c08865c65ae4a4615a1b6d148eb915bbf74297363257f945163c8	2026-02-25 10:51:18.509464+08
042b_add_ops_system_metrics_switch_count.sql	ee5428fb36a497799cb92ceffbbdc8e257a6e0c27aaae072152cac9bbc4d7dd8	2026-02-25 10:51:18.521286+08
043_add_usage_cleanup_cancel_audit.sql	4d3a22daea84e74d902ee1a6cec44e8985372e127c085a7dec2e30a922241585	2026-02-25 10:51:18.52656+08
043b_add_group_invalid_request_fallback.sql	7667812b71f86bb010afd0807c709c2415ca585d08995967982def2b35b46b9d	2026-02-25 10:51:18.534727+08
044_add_user_totp.sql	744b989d9a852d3e5871149f5ae83494ed84ac00861c6f40494506c63195cb74	2026-02-25 10:51:18.54211+08
044b_add_group_mcp_xml_inject.sql	944e8ed8950dc9c2cf95ee62bcf342ea2e15a771895b43da87efec85db921c31	2026-02-25 10:51:18.550486+08
045_add_accounts_extra_index.sql	c8e0948f88871aa79af0de0898d3aa6e14106e7a31b1fc6ae61bda57ebd1f7a4	2026-02-25 10:51:18.556773+08
045_add_announcements.sql	6b2df139a5004bdfd2ea9d6fc39d28eec973340ba045472fb399856f49b46f99	2026-02-25 10:51:18.563166+08
045_add_api_key_quota.sql	d0602924f128c5bbf468924f5ec990f87cd7636619bf9b52b17bb015abf37d55	2026-02-25 10:51:18.585475+08
046_add_sora_accounts.sql	b86a3243f965c569a97d96f5203853744e088f3c2b024ae243203ff96df8ceeb	2026-02-25 10:51:18.594363+08
046_add_usage_log_reasoning_effort.sql	88b1408cab98801d90c717efb8002a5f5a75a509f424df0fc16d36100a1592e3	2026-02-25 10:51:18.603963+08
046b_add_group_supported_model_scopes.sql	5fa393ae8645c6cb7c019bc2f2e14f4b588e88719f56af4bde6160d37186fd2b	2026-02-25 10:51:18.608343+08
047_add_sora_pricing_and_media_type.sql	d806f44a7dd70b8a2f7abadcb5cc8bf75679db242dacab9c8a69886bc17ed10a	2026-02-25 10:51:18.612989+08
047_add_user_group_rate_multipliers.sql	b866ed6d784e7b43f48d6b8e5b138c8b040354ff2fc2be4569fa810b779e9c16	2026-02-25 10:51:18.619695+08
048_add_error_passthrough_rules.sql	f86707582e0dab5f2f1e7f9abc8f0be7ebe36e1544e4a559be808d8b5712db3f	2026-02-25 10:51:18.62816+08
049_unify_antigravity_model_mapping.sql	e27c5615388f95c3d638a572f33a570e9a0f89efaae2f88cafdd3a169cb64f56	2026-02-25 10:51:18.639459+08
050_map_opus46_to_opus45.sql	dd4b8b866fdbaa5dc2ce0750be69faa65a7368fef1e937e3ab923bc35d5d5bd5	2026-02-25 10:51:18.644923+08
051_migrate_opus45_to_opus46_thinking.sql	17896dac51029a101369bbe80a7c76f2a82838d890e2248d38f38462a931acd2	2026-02-25 10:51:18.652856+08
052_add_group_sort_order.sql	f49cc4729d382b30f1477a2423d0072e9b0203128b1dd01c7c6ac6ee4c050faa	2026-02-25 10:51:18.657391+08
052_migrate_upstream_to_apikey.sql	d2ea657ec24995664a8ddc1bfb9c3fe317646c7bcd12517dee8478bc6c36244a	2026-02-25 10:51:18.665963+08
053_add_security_secrets.sql	9a17a5c2d98eea3656d36e7eb6c5238e839a40bf06a6fb599013bfbace8e0b46	2026-02-25 10:51:18.669847+08
053_add_skip_monitoring_to_error_passthrough.sql	70dceedd55b14bbca64d760ebdd857481b6d6c34367d308ca8a4f86b0374ed1e	2026-02-25 10:51:18.679651+08
054_add_ldap_identity.sql	c983be099e3866b5aa2c0fdcd3c9898515c182e8a0a3fb9398c400f32a5f31b3	2026-02-25 10:51:18.68433+08
054_drop_legacy_cache_columns.sql	82de761156e03876653e7a6a4eee883cd927847036f779b0b9f34c42a8af7a7d	2026-02-25 10:51:18.697294+08
054_ops_system_logs.sql	a47aa0fdab66ba60ac57bf127254e86060bfe681735559751fec2386b6c36541	2026-02-25 10:51:18.703222+08
055_add_cache_ttl_overridden.sql	3d05c9ffe4aaffec1cb7e482bc45fc5e63986b856548956795b33421280329a0	2026-02-25 10:51:18.723864+08
056_add_api_key_last_used_at.sql	e3f815389414fd17e3c42db46e6ade842ffea87077965f2076356f4ee8f30bc2	2026-02-25 10:51:18.728543+08
057_add_idempotency_records.sql	879aa2f0803121671ca75525c861aac6711ee52ac2e5e69967ce8a872754819e	2026-02-25 10:51:18.733115+08
058_add_sonnet46_to_model_mapping.sql	b417bcfe71f6f60837d35bfff3ac3089300ea18c3d577a00f81d4861aa889c03	2026-02-25 10:51:18.743243+08
059_add_gemini31_pro_to_model_mapping.sql	04e541c4600ccf3e54afae9506bb17db3335e02c0942958c120717147337e20f	2026-02-25 10:51:18.747465+08
\.


--
-- Data for Name: security_secrets; Type: TABLE DATA; Schema: public; Owner: sub2api
--

COPY public.security_secrets (id, key, value, created_at, updated_at) FROM stdin;
1	jwt_secret	e535f28c6dd5d43d6635e679720f2e36f8029c4d38192c32d2e818b4e356ee5f	2026-02-25 10:51:18.856305+08	2026-02-25 10:51:18.856305+08
\.


--
-- Data for Name: settings; Type: TABLE DATA; Schema: public; Owner: sub2api
--

COPY public.settings (id, key, value, updated_at) FROM stdin;
1	ops_runtime_log_config	{"level":"info","enable_sampling":false,"sampling_initial":100,"sampling_thereafter":100,"caller":true,"stacktrace_level":"error","retention_days":30}	2026-02-25 10:51:19.655793+08
2	ops_email_notification_config	{"alert":{"enabled":true,"recipients":[],"min_severity":"","rate_limit_per_hour":0,"batching_window_seconds":0,"include_resolved_alerts":false},"report":{"enabled":false,"recipients":[],"daily_summary_enabled":false,"daily_summary_schedule":"0 9 * * *","weekly_summary_enabled":false,"weekly_summary_schedule":"0 9 * * 1","error_digest_enabled":false,"error_digest_schedule":"0 9 * * *","error_digest_min_count":10,"account_health_enabled":false,"account_health_schedule":"0 9 * * *","account_health_error_rate_threshold":10}}	2026-02-25 10:51:19.675706+08
3	ops_alert_runtime_settings	{"evaluation_interval_seconds":60,"distributed_lock":{"enabled":true,"key":"ops:alert:evaluator:leader","ttl_seconds":30},"silencing":{"enabled":false,"global_until_rfc3339":"","global_reason":""},"thresholds":{}}	2026-02-25 10:51:19.675893+08
33	ldap_insecure_skip_verify	false	2026-02-25 11:17:40.542185+08
62	ldap_bind_dn	CN=ldap,OU=service,OU=lrgame,DC=lr,DC=local	2026-02-25 11:17:40.542185+08
13	default_balance	0.00000000	2026-02-25 11:17:40.542185+08
22	ops_monitoring_enabled	true	2026-02-25 11:17:40.542185+08
58	ldap_bind_password	oC#ma*N728	2026-02-25 11:17:40.542185+08
20	identity_patch_prompt		2026-02-25 11:17:40.542185+08
32	smtp_use_tls	false	2026-02-25 11:17:40.542185+08
56	linuxdo_connect_redirect_url		2026-02-25 11:17:40.542185+08
26	home_content		2026-02-25 11:17:40.542185+08
34	email_verify_enabled	false	2026-02-25 11:17:40.542185+08
35	ldap_host	lr.local	2026-02-25 11:17:40.542185+08
14	enable_identity_patch	true	2026-02-25 11:17:40.542185+08
53	ldap_uid_attr	uid	2026-02-25 11:17:40.542185+08
24	ldap_department_attr	department	2026-02-25 11:17:40.542185+08
31	promo_code_enabled	true	2026-02-25 11:17:40.542185+08
57	ldap_user_filter	({login_attr}={login})	2026-02-25 11:17:40.542185+08
15	registration_enabled	true	2026-02-25 11:17:40.542185+08
49	smtp_from		2026-02-25 11:17:40.542185+08
37	ops_realtime_monitoring_enabled	true	2026-02-25 11:17:40.542185+08
6	totp_enabled	false	2026-02-25 11:17:40.542185+08
8	ldap_sync_enabled	true	2026-02-25 11:17:40.542185+08
50	ldap_sync_interval_minutes	1440	2026-02-25 11:17:40.542185+08
60	default_concurrency	5	2026-02-25 11:17:40.542185+08
39	smtp_from_name		2026-02-25 11:17:40.542185+08
17	ldap_display_name_attr	displayName	2026-02-25 11:17:40.542185+08
30	contact_info		2026-02-25 11:17:40.542185+08
12	doc_url		2026-02-25 11:17:40.542185+08
41	ldap_use_tls	false	2026-02-25 11:17:40.542185+08
52	purchase_subscription_url		2026-02-25 11:17:40.542185+08
27	smtp_host		2026-02-25 11:17:40.542185+08
19	fallback_model_anthropic	claude-3-5-sonnet-20241022	2026-02-25 11:17:40.542185+08
48	ops_metrics_interval_seconds	60	2026-02-25 11:17:40.542185+08
5	smtp_port	587	2026-02-25 11:17:40.542185+08
11	smtp_username		2026-02-25 11:17:40.542185+08
55	linuxdo_connect_client_id		2026-02-25 11:17:40.542185+08
7	ldap_port	389	2026-02-25 11:17:40.542185+08
124	ldap_last_sync_at	2026-02-25T03:18:18Z	2026-02-25 11:18:18.75709+08
25	site_subtitle	Subscription to API Conversion Platform	2026-02-25 11:17:40.542185+08
18	hide_ccs_import_button	false	2026-02-25 11:17:40.542185+08
36	purchase_subscription_enabled	false	2026-02-25 11:17:40.542185+08
4	ops_query_mode_default	auto	2026-02-25 11:17:40.542185+08
40	linuxdo_connect_enabled	false	2026-02-25 11:17:40.542185+08
61	fallback_model_antigravity	gemini-2.5-pro	2026-02-25 11:17:40.542185+08
42	ldap_start_tls	false	2026-02-25 11:17:40.542185+08
9	enable_model_fallback	false	2026-02-25 11:17:40.542185+08
44	api_base_url		2026-02-25 11:17:40.542185+08
54	turnstile_enabled	false	2026-02-25 11:17:40.542185+08
46	ldap_enabled	true	2026-02-25 11:17:40.542185+08
16	ldap_login_attr	sAMAccountName	2026-02-25 11:17:40.542185+08
28	ldap_email_attr	mail	2026-02-25 11:17:40.542185+08
59	ldap_allowed_group_dns	[]	2026-02-25 11:17:40.542185+08
10	fallback_model_openai	gpt-4o	2026-02-25 11:17:40.542185+08
45	invitation_code_enabled	false	2026-02-25 11:17:40.542185+08
21	turnstile_site_key		2026-02-25 11:17:40.542185+08
23	ldap_user_base_dn	OU=lrgame,DC=lr,DC=local	2026-02-25 11:17:40.542185+08
63	ldap_group_mappings	[]	2026-02-25 11:17:40.542185+08
43	site_name	Sub2API	2026-02-25 11:17:40.542185+08
47	site_logo		2026-02-25 11:17:40.542185+08
29	ldap_group_attr	memberOf	2026-02-25 11:17:40.542185+08
51	fallback_model_gemini	gemini-2.5-pro	2026-02-25 11:17:40.542185+08
38	password_reset_enabled	false	2026-02-25 11:17:40.542185+08
\.


--
-- Data for Name: sora_accounts; Type: TABLE DATA; Schema: public; Owner: sub2api
--

COPY public.sora_accounts (account_id, access_token, refresh_token, session_token, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: usage_cleanup_tasks; Type: TABLE DATA; Schema: public; Owner: sub2api
--

COPY public.usage_cleanup_tasks (id, status, filters, created_by, deleted_rows, error_message, started_at, finished_at, created_at, updated_at, canceled_by, canceled_at) FROM stdin;
\.


--
-- Data for Name: usage_dashboard_aggregation_watermark; Type: TABLE DATA; Schema: public; Owner: sub2api
--

COPY public.usage_dashboard_aggregation_watermark (id, last_aggregated_at, updated_at) FROM stdin;
1	2026-02-25 13:38:39.802478+08	2026-02-25 13:38:39.807921+08
\.


--
-- Data for Name: usage_dashboard_daily; Type: TABLE DATA; Schema: public; Owner: sub2api
--

COPY public.usage_dashboard_daily (bucket_date, total_requests, input_tokens, output_tokens, cache_creation_tokens, cache_read_tokens, total_cost, actual_cost, total_duration_ms, active_users, computed_at) FROM stdin;
\.


--
-- Data for Name: usage_dashboard_daily_users; Type: TABLE DATA; Schema: public; Owner: sub2api
--

COPY public.usage_dashboard_daily_users (bucket_date, user_id) FROM stdin;
\.


--
-- Data for Name: usage_dashboard_hourly; Type: TABLE DATA; Schema: public; Owner: sub2api
--

COPY public.usage_dashboard_hourly (bucket_start, total_requests, input_tokens, output_tokens, cache_creation_tokens, cache_read_tokens, total_cost, actual_cost, total_duration_ms, active_users, computed_at) FROM stdin;
\.


--
-- Data for Name: usage_dashboard_hourly_users; Type: TABLE DATA; Schema: public; Owner: sub2api
--

COPY public.usage_dashboard_hourly_users (bucket_start, user_id) FROM stdin;
\.


--
-- Data for Name: usage_logs; Type: TABLE DATA; Schema: public; Owner: sub2api
--

COPY public.usage_logs (id, user_id, api_key_id, account_id, request_id, model, input_tokens, output_tokens, cache_creation_tokens, cache_read_tokens, cache_creation_5m_tokens, cache_creation_1h_tokens, input_cost, output_cost, cache_creation_cost, cache_read_cost, total_cost, actual_cost, stream, duration_ms, created_at, group_id, subscription_id, rate_multiplier, first_token_ms, billing_type, user_agent, image_count, image_size, ip_address, account_rate_multiplier, reasoning_effort, media_type, cache_ttl_overridden) FROM stdin;
\.


--
-- Data for Name: user_allowed_groups; Type: TABLE DATA; Schema: public; Owner: sub2api
--

COPY public.user_allowed_groups (user_id, group_id, created_at) FROM stdin;
\.


--
-- Data for Name: user_attribute_definitions; Type: TABLE DATA; Schema: public; Owner: sub2api
--

COPY public.user_attribute_definitions (id, key, name, description, type, options, required, validation, placeholder, display_order, enabled, created_at, updated_at, deleted_at) FROM stdin;
1	wechat	微信	用户微信号	text	[]	f	{}	请输入微信号	0	t	2026-02-25 10:51:18.205475+08	2026-02-25 10:51:18.205475+08	2026-02-25 10:51:18.205475+08
\.


--
-- Data for Name: user_attribute_values; Type: TABLE DATA; Schema: public; Owner: sub2api
--

COPY public.user_attribute_values (id, user_id, attribute_id, value, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: user_group_rate_multipliers; Type: TABLE DATA; Schema: public; Owner: sub2api
--

COPY public.user_group_rate_multipliers (user_id, group_id, rate_multiplier, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: user_ldap_profiles; Type: TABLE DATA; Schema: public; Owner: sub2api
--

COPY public.user_ldap_profiles (user_id, ldap_uid, ldap_username, ldap_email, display_name, department, groups_hash, active, last_synced_at, created_at, updated_at) FROM stdin;
2	CN=王洪平,OU=运维组,OU=技术平台中心,OU=技术部,OU=lrgame,DC=lr,DC=local	wanghongping		王洪平	运维组	65b0d77cd05da5c56dd943c7769443fa54e40296c598699a268f326778c0d570	t	2026-02-25 11:19:31.471677+08	2026-02-25 11:17:52.626131+08	2026-02-25 11:19:31.471875+08
\.


--
-- Data for Name: user_subscriptions; Type: TABLE DATA; Schema: public; Owner: sub2api
--

COPY public.user_subscriptions (id, user_id, group_id, starts_at, expires_at, status, daily_window_start, weekly_window_start, monthly_window_start, daily_usage_usd, weekly_usage_usd, monthly_usage_usd, assigned_by, assigned_at, notes, created_at, updated_at, deleted_at) FROM stdin;
\.


--
-- Data for Name: users; Type: TABLE DATA; Schema: public; Owner: sub2api
--

COPY public.users (id, email, password_hash, role, balance, concurrency, status, created_at, updated_at, deleted_at, username, notes, wechat, totp_secret_encrypted, totp_enabled, totp_enabled_at, token_version, auth_source) FROM stdin;
1	admin@sub2api.local	$2a$10$mKBgHC.kvtTYxfTaID7ZneR1mLrtsLY8mXP2v9TH8z.7VLWRsWG4C	admin	0.00000000	5	active	2026-02-25 10:51:18.762616+08	2026-02-25 10:58:59.624594+08	\N				\N	f	\N	1	local
2	wanghongping@ldap.local	$2a$10$Ea782vCgtRI.XXtTMSxqE.vB6jXg/WZCEW8xfSg3.rvWJ9UZN5fyq	user	0.00000000	5	active	2026-02-25 11:17:52.616426+08	2026-02-25 11:19:31.468624+08	\N	王洪平			\N	f	\N	0	ldap
\.


--
-- Name: accounts_id_seq; Type: SEQUENCE SET; Schema: public; Owner: sub2api
--

SELECT pg_catalog.setval('public.accounts_id_seq', 1, false);


--
-- Name: announcement_reads_id_seq; Type: SEQUENCE SET; Schema: public; Owner: sub2api
--

SELECT pg_catalog.setval('public.announcement_reads_id_seq', 1, false);


--
-- Name: announcements_id_seq; Type: SEQUENCE SET; Schema: public; Owner: sub2api
--

SELECT pg_catalog.setval('public.announcements_id_seq', 1, false);


--
-- Name: api_keys_id_seq; Type: SEQUENCE SET; Schema: public; Owner: sub2api
--

SELECT pg_catalog.setval('public.api_keys_id_seq', 1, false);


--
-- Name: billing_usage_entries_id_seq; Type: SEQUENCE SET; Schema: public; Owner: sub2api
--

SELECT pg_catalog.setval('public.billing_usage_entries_id_seq', 1, false);


--
-- Name: error_passthrough_rules_id_seq; Type: SEQUENCE SET; Schema: public; Owner: sub2api
--

SELECT pg_catalog.setval('public.error_passthrough_rules_id_seq', 1, false);


--
-- Name: groups_id_seq; Type: SEQUENCE SET; Schema: public; Owner: sub2api
--

SELECT pg_catalog.setval('public.groups_id_seq', 1, true);


--
-- Name: idempotency_records_id_seq; Type: SEQUENCE SET; Schema: public; Owner: sub2api
--

SELECT pg_catalog.setval('public.idempotency_records_id_seq', 1, true);


--
-- Name: ops_alert_events_id_seq; Type: SEQUENCE SET; Schema: public; Owner: sub2api
--

SELECT pg_catalog.setval('public.ops_alert_events_id_seq', 1, false);


--
-- Name: ops_alert_rules_id_seq; Type: SEQUENCE SET; Schema: public; Owner: sub2api
--

SELECT pg_catalog.setval('public.ops_alert_rules_id_seq', 8, true);


--
-- Name: ops_error_logs_id_seq; Type: SEQUENCE SET; Schema: public; Owner: sub2api
--

SELECT pg_catalog.setval('public.ops_error_logs_id_seq', 1, false);


--
-- Name: ops_metrics_daily_id_seq; Type: SEQUENCE SET; Schema: public; Owner: sub2api
--

SELECT pg_catalog.setval('public.ops_metrics_daily_id_seq', 1, false);


--
-- Name: ops_metrics_hourly_id_seq; Type: SEQUENCE SET; Schema: public; Owner: sub2api
--

SELECT pg_catalog.setval('public.ops_metrics_hourly_id_seq', 1, false);


--
-- Name: ops_retry_attempts_id_seq; Type: SEQUENCE SET; Schema: public; Owner: sub2api
--

SELECT pg_catalog.setval('public.ops_retry_attempts_id_seq', 1, false);


--
-- Name: ops_system_log_cleanup_audits_id_seq; Type: SEQUENCE SET; Schema: public; Owner: sub2api
--

SELECT pg_catalog.setval('public.ops_system_log_cleanup_audits_id_seq', 1, false);


--
-- Name: ops_system_logs_id_seq; Type: SEQUENCE SET; Schema: public; Owner: sub2api
--

SELECT pg_catalog.setval('public.ops_system_logs_id_seq', 745, true);


--
-- Name: ops_system_metrics_id_seq; Type: SEQUENCE SET; Schema: public; Owner: sub2api
--

SELECT pg_catalog.setval('public.ops_system_metrics_id_seq', 171, true);


--
-- Name: orphan_allowed_groups_audit_id_seq; Type: SEQUENCE SET; Schema: public; Owner: sub2api
--

SELECT pg_catalog.setval('public.orphan_allowed_groups_audit_id_seq', 1, false);


--
-- Name: promo_code_usages_id_seq; Type: SEQUENCE SET; Schema: public; Owner: sub2api
--

SELECT pg_catalog.setval('public.promo_code_usages_id_seq', 1, false);


--
-- Name: promo_codes_id_seq; Type: SEQUENCE SET; Schema: public; Owner: sub2api
--

SELECT pg_catalog.setval('public.promo_codes_id_seq', 1, false);


--
-- Name: proxies_id_seq; Type: SEQUENCE SET; Schema: public; Owner: sub2api
--

SELECT pg_catalog.setval('public.proxies_id_seq', 1, false);


--
-- Name: redeem_codes_id_seq; Type: SEQUENCE SET; Schema: public; Owner: sub2api
--

SELECT pg_catalog.setval('public.redeem_codes_id_seq', 1, false);


--
-- Name: scheduler_outbox_id_seq; Type: SEQUENCE SET; Schema: public; Owner: sub2api
--

SELECT pg_catalog.setval('public.scheduler_outbox_id_seq', 1, false);


--
-- Name: security_secrets_id_seq; Type: SEQUENCE SET; Schema: public; Owner: sub2api
--

SELECT pg_catalog.setval('public.security_secrets_id_seq', 5, true);


--
-- Name: settings_id_seq; Type: SEQUENCE SET; Schema: public; Owner: sub2api
--

SELECT pg_catalog.setval('public.settings_id_seq', 188, true);


--
-- Name: usage_cleanup_tasks_id_seq; Type: SEQUENCE SET; Schema: public; Owner: sub2api
--

SELECT pg_catalog.setval('public.usage_cleanup_tasks_id_seq', 1, false);


--
-- Name: usage_logs_id_seq; Type: SEQUENCE SET; Schema: public; Owner: sub2api
--

SELECT pg_catalog.setval('public.usage_logs_id_seq', 1, false);


--
-- Name: user_attribute_definitions_id_seq; Type: SEQUENCE SET; Schema: public; Owner: sub2api
--

SELECT pg_catalog.setval('public.user_attribute_definitions_id_seq', 1, true);


--
-- Name: user_attribute_values_id_seq; Type: SEQUENCE SET; Schema: public; Owner: sub2api
--

SELECT pg_catalog.setval('public.user_attribute_values_id_seq', 1, false);


--
-- Name: user_subscriptions_id_seq; Type: SEQUENCE SET; Schema: public; Owner: sub2api
--

SELECT pg_catalog.setval('public.user_subscriptions_id_seq', 1, false);


--
-- Name: users_id_seq; Type: SEQUENCE SET; Schema: public; Owner: sub2api
--

SELECT pg_catalog.setval('public.users_id_seq', 2, true);


--
-- Name: account_groups account_groups_pkey; Type: CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.account_groups
    ADD CONSTRAINT account_groups_pkey PRIMARY KEY (account_id, group_id);


--
-- Name: accounts accounts_pkey; Type: CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.accounts
    ADD CONSTRAINT accounts_pkey PRIMARY KEY (id);


--
-- Name: announcement_reads announcement_reads_announcement_id_user_id_key; Type: CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.announcement_reads
    ADD CONSTRAINT announcement_reads_announcement_id_user_id_key UNIQUE (announcement_id, user_id);


--
-- Name: announcement_reads announcement_reads_pkey; Type: CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.announcement_reads
    ADD CONSTRAINT announcement_reads_pkey PRIMARY KEY (id);


--
-- Name: announcements announcements_pkey; Type: CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.announcements
    ADD CONSTRAINT announcements_pkey PRIMARY KEY (id);


--
-- Name: api_keys api_keys_key_key; Type: CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT api_keys_key_key UNIQUE (key);


--
-- Name: api_keys api_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT api_keys_pkey PRIMARY KEY (id);


--
-- Name: atlas_schema_revisions atlas_schema_revisions_pkey; Type: CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.atlas_schema_revisions
    ADD CONSTRAINT atlas_schema_revisions_pkey PRIMARY KEY (version);


--
-- Name: billing_usage_entries billing_usage_entries_pkey; Type: CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.billing_usage_entries
    ADD CONSTRAINT billing_usage_entries_pkey PRIMARY KEY (id);


--
-- Name: error_passthrough_rules error_passthrough_rules_pkey; Type: CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.error_passthrough_rules
    ADD CONSTRAINT error_passthrough_rules_pkey PRIMARY KEY (id);


--
-- Name: groups groups_pkey; Type: CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.groups
    ADD CONSTRAINT groups_pkey PRIMARY KEY (id);


--
-- Name: idempotency_records idempotency_records_pkey; Type: CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.idempotency_records
    ADD CONSTRAINT idempotency_records_pkey PRIMARY KEY (id);


--
-- Name: ops_alert_events ops_alert_events_pkey; Type: CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.ops_alert_events
    ADD CONSTRAINT ops_alert_events_pkey PRIMARY KEY (id);


--
-- Name: ops_alert_rules ops_alert_rules_pkey; Type: CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.ops_alert_rules
    ADD CONSTRAINT ops_alert_rules_pkey PRIMARY KEY (id);


--
-- Name: ops_error_logs ops_error_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.ops_error_logs
    ADD CONSTRAINT ops_error_logs_pkey PRIMARY KEY (id);


--
-- Name: ops_job_heartbeats ops_job_heartbeats_pkey; Type: CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.ops_job_heartbeats
    ADD CONSTRAINT ops_job_heartbeats_pkey PRIMARY KEY (job_name);


--
-- Name: ops_metrics_daily ops_metrics_daily_pkey; Type: CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.ops_metrics_daily
    ADD CONSTRAINT ops_metrics_daily_pkey PRIMARY KEY (id);


--
-- Name: ops_metrics_hourly ops_metrics_hourly_pkey; Type: CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.ops_metrics_hourly
    ADD CONSTRAINT ops_metrics_hourly_pkey PRIMARY KEY (id);


--
-- Name: ops_retry_attempts ops_retry_attempts_pkey; Type: CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.ops_retry_attempts
    ADD CONSTRAINT ops_retry_attempts_pkey PRIMARY KEY (id);


--
-- Name: ops_system_log_cleanup_audits ops_system_log_cleanup_audits_pkey; Type: CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.ops_system_log_cleanup_audits
    ADD CONSTRAINT ops_system_log_cleanup_audits_pkey PRIMARY KEY (id);


--
-- Name: ops_system_logs ops_system_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.ops_system_logs
    ADD CONSTRAINT ops_system_logs_pkey PRIMARY KEY (id);


--
-- Name: ops_system_metrics ops_system_metrics_pkey; Type: CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.ops_system_metrics
    ADD CONSTRAINT ops_system_metrics_pkey PRIMARY KEY (id);


--
-- Name: orphan_allowed_groups_audit orphan_allowed_groups_audit_pkey; Type: CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.orphan_allowed_groups_audit
    ADD CONSTRAINT orphan_allowed_groups_audit_pkey PRIMARY KEY (id);


--
-- Name: orphan_allowed_groups_audit orphan_allowed_groups_audit_user_id_group_id_key; Type: CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.orphan_allowed_groups_audit
    ADD CONSTRAINT orphan_allowed_groups_audit_user_id_group_id_key UNIQUE (user_id, group_id);


--
-- Name: promo_code_usages promo_code_usages_pkey; Type: CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.promo_code_usages
    ADD CONSTRAINT promo_code_usages_pkey PRIMARY KEY (id);


--
-- Name: promo_code_usages promo_code_usages_promo_code_id_user_id_key; Type: CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.promo_code_usages
    ADD CONSTRAINT promo_code_usages_promo_code_id_user_id_key UNIQUE (promo_code_id, user_id);


--
-- Name: promo_codes promo_codes_code_key; Type: CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.promo_codes
    ADD CONSTRAINT promo_codes_code_key UNIQUE (code);


--
-- Name: promo_codes promo_codes_pkey; Type: CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.promo_codes
    ADD CONSTRAINT promo_codes_pkey PRIMARY KEY (id);


--
-- Name: proxies proxies_pkey; Type: CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.proxies
    ADD CONSTRAINT proxies_pkey PRIMARY KEY (id);


--
-- Name: redeem_codes redeem_codes_code_key; Type: CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.redeem_codes
    ADD CONSTRAINT redeem_codes_code_key UNIQUE (code);


--
-- Name: redeem_codes redeem_codes_pkey; Type: CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.redeem_codes
    ADD CONSTRAINT redeem_codes_pkey PRIMARY KEY (id);


--
-- Name: scheduler_outbox scheduler_outbox_pkey; Type: CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.scheduler_outbox
    ADD CONSTRAINT scheduler_outbox_pkey PRIMARY KEY (id);


--
-- Name: schema_migrations schema_migrations_pkey; Type: CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.schema_migrations
    ADD CONSTRAINT schema_migrations_pkey PRIMARY KEY (filename);


--
-- Name: security_secrets security_secrets_key_key; Type: CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.security_secrets
    ADD CONSTRAINT security_secrets_key_key UNIQUE (key);


--
-- Name: security_secrets security_secrets_pkey; Type: CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.security_secrets
    ADD CONSTRAINT security_secrets_pkey PRIMARY KEY (id);


--
-- Name: settings settings_key_key; Type: CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.settings
    ADD CONSTRAINT settings_key_key UNIQUE (key);


--
-- Name: settings settings_pkey; Type: CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.settings
    ADD CONSTRAINT settings_pkey PRIMARY KEY (id);


--
-- Name: sora_accounts sora_accounts_pkey; Type: CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.sora_accounts
    ADD CONSTRAINT sora_accounts_pkey PRIMARY KEY (account_id);


--
-- Name: usage_cleanup_tasks usage_cleanup_tasks_pkey; Type: CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.usage_cleanup_tasks
    ADD CONSTRAINT usage_cleanup_tasks_pkey PRIMARY KEY (id);


--
-- Name: usage_dashboard_aggregation_watermark usage_dashboard_aggregation_watermark_pkey; Type: CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.usage_dashboard_aggregation_watermark
    ADD CONSTRAINT usage_dashboard_aggregation_watermark_pkey PRIMARY KEY (id);


--
-- Name: usage_dashboard_daily usage_dashboard_daily_pkey; Type: CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.usage_dashboard_daily
    ADD CONSTRAINT usage_dashboard_daily_pkey PRIMARY KEY (bucket_date);


--
-- Name: usage_dashboard_daily_users usage_dashboard_daily_users_pkey; Type: CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.usage_dashboard_daily_users
    ADD CONSTRAINT usage_dashboard_daily_users_pkey PRIMARY KEY (bucket_date, user_id);


--
-- Name: usage_dashboard_hourly usage_dashboard_hourly_pkey; Type: CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.usage_dashboard_hourly
    ADD CONSTRAINT usage_dashboard_hourly_pkey PRIMARY KEY (bucket_start);


--
-- Name: usage_dashboard_hourly_users usage_dashboard_hourly_users_pkey; Type: CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.usage_dashboard_hourly_users
    ADD CONSTRAINT usage_dashboard_hourly_users_pkey PRIMARY KEY (bucket_start, user_id);


--
-- Name: usage_logs usage_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.usage_logs
    ADD CONSTRAINT usage_logs_pkey PRIMARY KEY (id);


--
-- Name: user_allowed_groups user_allowed_groups_pkey; Type: CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.user_allowed_groups
    ADD CONSTRAINT user_allowed_groups_pkey PRIMARY KEY (user_id, group_id);


--
-- Name: user_attribute_definitions user_attribute_definitions_pkey; Type: CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.user_attribute_definitions
    ADD CONSTRAINT user_attribute_definitions_pkey PRIMARY KEY (id);


--
-- Name: user_attribute_values user_attribute_values_pkey; Type: CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.user_attribute_values
    ADD CONSTRAINT user_attribute_values_pkey PRIMARY KEY (id);


--
-- Name: user_attribute_values user_attribute_values_user_id_attribute_id_key; Type: CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.user_attribute_values
    ADD CONSTRAINT user_attribute_values_user_id_attribute_id_key UNIQUE (user_id, attribute_id);


--
-- Name: user_group_rate_multipliers user_group_rate_multipliers_pkey; Type: CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.user_group_rate_multipliers
    ADD CONSTRAINT user_group_rate_multipliers_pkey PRIMARY KEY (user_id, group_id);


--
-- Name: user_ldap_profiles user_ldap_profiles_pkey; Type: CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.user_ldap_profiles
    ADD CONSTRAINT user_ldap_profiles_pkey PRIMARY KEY (user_id);


--
-- Name: user_subscriptions user_subscriptions_pkey; Type: CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.user_subscriptions
    ADD CONSTRAINT user_subscriptions_pkey PRIMARY KEY (id);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: billing_usage_entries_usage_log_id_unique; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE UNIQUE INDEX billing_usage_entries_usage_log_id_unique ON public.billing_usage_entries USING btree (usage_log_id);


--
-- Name: groups_name_unique_active; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE UNIQUE INDEX groups_name_unique_active ON public.groups USING btree (name) WHERE (deleted_at IS NULL);


--
-- Name: idx_account_groups_group_id; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_account_groups_group_id ON public.account_groups USING btree (group_id);


--
-- Name: idx_account_groups_priority; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_account_groups_priority ON public.account_groups USING btree (priority);


--
-- Name: idx_accounts_deleted_at; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_accounts_deleted_at ON public.accounts USING btree (deleted_at);


--
-- Name: idx_accounts_extra_gin; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_accounts_extra_gin ON public.accounts USING gin (extra);


--
-- Name: idx_accounts_last_used_at; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_accounts_last_used_at ON public.accounts USING btree (last_used_at);


--
-- Name: idx_accounts_overload_until; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_accounts_overload_until ON public.accounts USING btree (overload_until);


--
-- Name: idx_accounts_platform; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_accounts_platform ON public.accounts USING btree (platform);


--
-- Name: idx_accounts_priority; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_accounts_priority ON public.accounts USING btree (priority);


--
-- Name: idx_accounts_proxy_id; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_accounts_proxy_id ON public.accounts USING btree (proxy_id);


--
-- Name: idx_accounts_rate_limit_reset_at; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_accounts_rate_limit_reset_at ON public.accounts USING btree (rate_limit_reset_at);


--
-- Name: idx_accounts_rate_limited_at; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_accounts_rate_limited_at ON public.accounts USING btree (rate_limited_at);


--
-- Name: idx_accounts_schedulable; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_accounts_schedulable ON public.accounts USING btree (schedulable);


--
-- Name: idx_accounts_status; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_accounts_status ON public.accounts USING btree (status);


--
-- Name: idx_accounts_temp_unschedulable_until; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_accounts_temp_unschedulable_until ON public.accounts USING btree (temp_unschedulable_until) WHERE (deleted_at IS NULL);


--
-- Name: idx_accounts_type; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_accounts_type ON public.accounts USING btree (type);


--
-- Name: idx_announcement_reads_announcement_id; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_announcement_reads_announcement_id ON public.announcement_reads USING btree (announcement_id);


--
-- Name: idx_announcement_reads_read_at; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_announcement_reads_read_at ON public.announcement_reads USING btree (read_at);


--
-- Name: idx_announcement_reads_user_id; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_announcement_reads_user_id ON public.announcement_reads USING btree (user_id);


--
-- Name: idx_announcements_created_at; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_announcements_created_at ON public.announcements USING btree (created_at);


--
-- Name: idx_announcements_ends_at; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_announcements_ends_at ON public.announcements USING btree (ends_at);


--
-- Name: idx_announcements_starts_at; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_announcements_starts_at ON public.announcements USING btree (starts_at);


--
-- Name: idx_announcements_status; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_announcements_status ON public.announcements USING btree (status);


--
-- Name: idx_api_keys_deleted_at; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_api_keys_deleted_at ON public.api_keys USING btree (deleted_at);


--
-- Name: idx_api_keys_expires_at; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_api_keys_expires_at ON public.api_keys USING btree (expires_at) WHERE (deleted_at IS NULL);


--
-- Name: idx_api_keys_group_id; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_api_keys_group_id ON public.api_keys USING btree (group_id);


--
-- Name: idx_api_keys_last_used_at; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_api_keys_last_used_at ON public.api_keys USING btree (last_used_at) WHERE (deleted_at IS NULL);


--
-- Name: idx_api_keys_quota_quota_used; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_api_keys_quota_quota_used ON public.api_keys USING btree (quota, quota_used) WHERE (deleted_at IS NULL);


--
-- Name: idx_api_keys_status; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_api_keys_status ON public.api_keys USING btree (status);


--
-- Name: idx_api_keys_user_id; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_api_keys_user_id ON public.api_keys USING btree (user_id);


--
-- Name: idx_billing_usage_entries_created_at; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_billing_usage_entries_created_at ON public.billing_usage_entries USING btree (created_at);


--
-- Name: idx_billing_usage_entries_user_time; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_billing_usage_entries_user_time ON public.billing_usage_entries USING btree (user_id, created_at);


--
-- Name: idx_error_passthrough_rules_enabled; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_error_passthrough_rules_enabled ON public.error_passthrough_rules USING btree (enabled);


--
-- Name: idx_error_passthrough_rules_priority; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_error_passthrough_rules_priority ON public.error_passthrough_rules USING btree (priority);


--
-- Name: idx_groups_claude_code_only; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_groups_claude_code_only ON public.groups USING btree (claude_code_only) WHERE (deleted_at IS NULL);


--
-- Name: idx_groups_deleted_at; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_groups_deleted_at ON public.groups USING btree (deleted_at);


--
-- Name: idx_groups_fallback_group_id; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_groups_fallback_group_id ON public.groups USING btree (fallback_group_id) WHERE ((deleted_at IS NULL) AND (fallback_group_id IS NOT NULL));


--
-- Name: idx_groups_fallback_group_id_on_invalid_request; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_groups_fallback_group_id_on_invalid_request ON public.groups USING btree (fallback_group_id_on_invalid_request) WHERE ((deleted_at IS NULL) AND (fallback_group_id_on_invalid_request IS NOT NULL));


--
-- Name: idx_groups_is_exclusive; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_groups_is_exclusive ON public.groups USING btree (is_exclusive);


--
-- Name: idx_groups_platform; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_groups_platform ON public.groups USING btree (platform);


--
-- Name: idx_groups_sort_order; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_groups_sort_order ON public.groups USING btree (sort_order);


--
-- Name: idx_groups_status; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_groups_status ON public.groups USING btree (status);


--
-- Name: idx_groups_subscription_type; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_groups_subscription_type ON public.groups USING btree (subscription_type);


--
-- Name: idx_idempotency_records_expires_at; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_idempotency_records_expires_at ON public.idempotency_records USING btree (expires_at);


--
-- Name: idx_idempotency_records_scope_key; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE UNIQUE INDEX idx_idempotency_records_scope_key ON public.idempotency_records USING btree (scope, idempotency_key_hash);


--
-- Name: idx_idempotency_records_status_locked_until; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_idempotency_records_status_locked_until ON public.idempotency_records USING btree (status, locked_until);


--
-- Name: idx_ops_alert_events_fired_at; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_ops_alert_events_fired_at ON public.ops_alert_events USING btree (fired_at DESC);


--
-- Name: idx_ops_alert_events_rule_status; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_ops_alert_events_rule_status ON public.ops_alert_events USING btree (rule_id, status);


--
-- Name: idx_ops_alert_rules_enabled; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_ops_alert_rules_enabled ON public.ops_alert_rules USING btree (enabled);


--
-- Name: idx_ops_alert_rules_name_unique; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE UNIQUE INDEX idx_ops_alert_rules_name_unique ON public.ops_alert_rules USING btree (name);


--
-- Name: idx_ops_error_logs_account_time; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_ops_error_logs_account_time ON public.ops_error_logs USING btree (account_id, created_at DESC) WHERE (account_id IS NOT NULL);


--
-- Name: idx_ops_error_logs_client_request_id; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_ops_error_logs_client_request_id ON public.ops_error_logs USING btree (client_request_id);


--
-- Name: idx_ops_error_logs_client_request_id_trgm; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_ops_error_logs_client_request_id_trgm ON public.ops_error_logs USING gin (client_request_id public.gin_trgm_ops);


--
-- Name: idx_ops_error_logs_created_at; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_ops_error_logs_created_at ON public.ops_error_logs USING btree (created_at DESC);


--
-- Name: idx_ops_error_logs_error_message_trgm; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_ops_error_logs_error_message_trgm ON public.ops_error_logs USING gin (error_message public.gin_trgm_ops);


--
-- Name: idx_ops_error_logs_group_time; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_ops_error_logs_group_time ON public.ops_error_logs USING btree (group_id, created_at DESC) WHERE (group_id IS NOT NULL);


--
-- Name: idx_ops_error_logs_is_count_tokens; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_ops_error_logs_is_count_tokens ON public.ops_error_logs USING btree (is_count_tokens) WHERE (is_count_tokens = true);


--
-- Name: idx_ops_error_logs_phase_time; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_ops_error_logs_phase_time ON public.ops_error_logs USING btree (error_phase, created_at DESC);


--
-- Name: idx_ops_error_logs_platform_time; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_ops_error_logs_platform_time ON public.ops_error_logs USING btree (platform, created_at DESC);


--
-- Name: idx_ops_error_logs_request_id; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_ops_error_logs_request_id ON public.ops_error_logs USING btree (request_id);


--
-- Name: idx_ops_error_logs_request_id_trgm; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_ops_error_logs_request_id_trgm ON public.ops_error_logs USING gin (request_id public.gin_trgm_ops);


--
-- Name: idx_ops_error_logs_resolved_time; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_ops_error_logs_resolved_time ON public.ops_error_logs USING btree (resolved, created_at DESC);


--
-- Name: idx_ops_error_logs_status_time; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_ops_error_logs_status_time ON public.ops_error_logs USING btree (status_code, created_at DESC);


--
-- Name: idx_ops_error_logs_type_time; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_ops_error_logs_type_time ON public.ops_error_logs USING btree (error_type, created_at DESC);


--
-- Name: idx_ops_error_logs_unresolved_time; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_ops_error_logs_unresolved_time ON public.ops_error_logs USING btree (created_at DESC) WHERE (resolved = false);


--
-- Name: idx_ops_metrics_daily_bucket; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_ops_metrics_daily_bucket ON public.ops_metrics_daily USING btree (bucket_date DESC);


--
-- Name: idx_ops_metrics_daily_group_bucket; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_ops_metrics_daily_group_bucket ON public.ops_metrics_daily USING btree (group_id, bucket_date DESC) WHERE ((group_id IS NOT NULL) AND (group_id <> 0));


--
-- Name: idx_ops_metrics_daily_platform_bucket; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_ops_metrics_daily_platform_bucket ON public.ops_metrics_daily USING btree (platform, bucket_date DESC) WHERE ((platform IS NOT NULL) AND ((platform)::text <> ''::text) AND (group_id IS NULL));


--
-- Name: idx_ops_metrics_daily_unique_dim; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE UNIQUE INDEX idx_ops_metrics_daily_unique_dim ON public.ops_metrics_daily USING btree (bucket_date, COALESCE(platform, ''::character varying), COALESCE(group_id, (0)::bigint));


--
-- Name: idx_ops_metrics_hourly_bucket; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_ops_metrics_hourly_bucket ON public.ops_metrics_hourly USING btree (bucket_start DESC);


--
-- Name: idx_ops_metrics_hourly_group_bucket; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_ops_metrics_hourly_group_bucket ON public.ops_metrics_hourly USING btree (group_id, bucket_start DESC) WHERE ((group_id IS NOT NULL) AND (group_id <> 0));


--
-- Name: idx_ops_metrics_hourly_platform_bucket; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_ops_metrics_hourly_platform_bucket ON public.ops_metrics_hourly USING btree (platform, bucket_start DESC) WHERE ((platform IS NOT NULL) AND ((platform)::text <> ''::text) AND (group_id IS NULL));


--
-- Name: idx_ops_metrics_hourly_unique_dim; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE UNIQUE INDEX idx_ops_metrics_hourly_unique_dim ON public.ops_metrics_hourly USING btree (bucket_start, COALESCE(platform, ''::character varying), COALESCE(group_id, (0)::bigint));


--
-- Name: idx_ops_retry_attempts_created_at; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_ops_retry_attempts_created_at ON public.ops_retry_attempts USING btree (created_at DESC);


--
-- Name: idx_ops_retry_attempts_source_error; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_ops_retry_attempts_source_error ON public.ops_retry_attempts USING btree (source_error_id, created_at DESC) WHERE (source_error_id IS NOT NULL);


--
-- Name: idx_ops_retry_attempts_success_time; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_ops_retry_attempts_success_time ON public.ops_retry_attempts USING btree (success, created_at DESC);


--
-- Name: idx_ops_retry_attempts_unique_active; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE UNIQUE INDEX idx_ops_retry_attempts_unique_active ON public.ops_retry_attempts USING btree (source_error_id) WHERE ((source_error_id IS NOT NULL) AND ((status)::text = ANY ((ARRAY['queued'::character varying, 'running'::character varying])::text[])));


--
-- Name: idx_ops_system_log_cleanup_audits_created_at; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_ops_system_log_cleanup_audits_created_at ON public.ops_system_log_cleanup_audits USING btree (created_at DESC, id DESC);


--
-- Name: idx_ops_system_logs_account_id_created_at; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_ops_system_logs_account_id_created_at ON public.ops_system_logs USING btree (account_id, created_at DESC);


--
-- Name: idx_ops_system_logs_client_request_id; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_ops_system_logs_client_request_id ON public.ops_system_logs USING btree (client_request_id);


--
-- Name: idx_ops_system_logs_component_created_at; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_ops_system_logs_component_created_at ON public.ops_system_logs USING btree (component, created_at DESC);


--
-- Name: idx_ops_system_logs_created_at_id; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_ops_system_logs_created_at_id ON public.ops_system_logs USING btree (created_at DESC, id DESC);


--
-- Name: idx_ops_system_logs_level_created_at; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_ops_system_logs_level_created_at ON public.ops_system_logs USING btree (level, created_at DESC);


--
-- Name: idx_ops_system_logs_message_search; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_ops_system_logs_message_search ON public.ops_system_logs USING gin (to_tsvector('simple'::regconfig, COALESCE(message, ''::text)));


--
-- Name: idx_ops_system_logs_platform_model_created_at; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_ops_system_logs_platform_model_created_at ON public.ops_system_logs USING btree (platform, model, created_at DESC);


--
-- Name: idx_ops_system_logs_request_id; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_ops_system_logs_request_id ON public.ops_system_logs USING btree (request_id);


--
-- Name: idx_ops_system_logs_user_id_created_at; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_ops_system_logs_user_id_created_at ON public.ops_system_logs USING btree (user_id, created_at DESC);


--
-- Name: idx_ops_system_metrics_created_at; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_ops_system_metrics_created_at ON public.ops_system_metrics USING btree (created_at DESC);


--
-- Name: idx_ops_system_metrics_group_time; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_ops_system_metrics_group_time ON public.ops_system_metrics USING btree (group_id, created_at DESC) WHERE (group_id IS NOT NULL);


--
-- Name: idx_ops_system_metrics_platform_time; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_ops_system_metrics_platform_time ON public.ops_system_metrics USING btree (platform, created_at DESC) WHERE ((platform IS NOT NULL) AND ((platform)::text <> ''::text) AND (group_id IS NULL));


--
-- Name: idx_ops_system_metrics_window_time; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_ops_system_metrics_window_time ON public.ops_system_metrics USING btree (window_minutes, created_at DESC);


--
-- Name: idx_orphan_allowed_groups_audit_user_id; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_orphan_allowed_groups_audit_user_id ON public.orphan_allowed_groups_audit USING btree (user_id);


--
-- Name: idx_promo_code_usages_promo_code_id; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_promo_code_usages_promo_code_id ON public.promo_code_usages USING btree (promo_code_id);


--
-- Name: idx_promo_code_usages_user_id; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_promo_code_usages_user_id ON public.promo_code_usages USING btree (user_id);


--
-- Name: idx_promo_codes_expires_at; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_promo_codes_expires_at ON public.promo_codes USING btree (expires_at);


--
-- Name: idx_promo_codes_status; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_promo_codes_status ON public.promo_codes USING btree (status);


--
-- Name: idx_proxies_deleted_at; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_proxies_deleted_at ON public.proxies USING btree (deleted_at);


--
-- Name: idx_proxies_status; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_proxies_status ON public.proxies USING btree (status);


--
-- Name: idx_redeem_codes_group_id; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_redeem_codes_group_id ON public.redeem_codes USING btree (group_id);


--
-- Name: idx_redeem_codes_status; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_redeem_codes_status ON public.redeem_codes USING btree (status);


--
-- Name: idx_redeem_codes_used_by; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_redeem_codes_used_by ON public.redeem_codes USING btree (used_by);


--
-- Name: idx_scheduler_outbox_created_at; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_scheduler_outbox_created_at ON public.scheduler_outbox USING btree (created_at);


--
-- Name: idx_security_secrets_key; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_security_secrets_key ON public.security_secrets USING btree (key);


--
-- Name: idx_usage_cleanup_tasks_canceled_at; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_usage_cleanup_tasks_canceled_at ON public.usage_cleanup_tasks USING btree (canceled_at DESC);


--
-- Name: idx_usage_cleanup_tasks_created_at; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_usage_cleanup_tasks_created_at ON public.usage_cleanup_tasks USING btree (created_at DESC);


--
-- Name: idx_usage_cleanup_tasks_status_created_at; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_usage_cleanup_tasks_status_created_at ON public.usage_cleanup_tasks USING btree (status, created_at DESC);


--
-- Name: idx_usage_dashboard_daily_bucket_date; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_usage_dashboard_daily_bucket_date ON public.usage_dashboard_daily USING btree (bucket_date DESC);


--
-- Name: idx_usage_dashboard_daily_users_bucket_date; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_usage_dashboard_daily_users_bucket_date ON public.usage_dashboard_daily_users USING btree (bucket_date);


--
-- Name: idx_usage_dashboard_hourly_bucket_start; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_usage_dashboard_hourly_bucket_start ON public.usage_dashboard_hourly USING btree (bucket_start DESC);


--
-- Name: idx_usage_dashboard_hourly_users_bucket_start; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_usage_dashboard_hourly_users_bucket_start ON public.usage_dashboard_hourly_users USING btree (bucket_start);


--
-- Name: idx_usage_logs_account_created_at; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_usage_logs_account_created_at ON public.usage_logs USING btree (account_id, created_at);


--
-- Name: idx_usage_logs_account_id; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_usage_logs_account_id ON public.usage_logs USING btree (account_id);


--
-- Name: idx_usage_logs_api_key_created_at; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_usage_logs_api_key_created_at ON public.usage_logs USING btree (api_key_id, created_at);


--
-- Name: idx_usage_logs_api_key_id; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_usage_logs_api_key_id ON public.usage_logs USING btree (api_key_id);


--
-- Name: idx_usage_logs_billing_type; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_usage_logs_billing_type ON public.usage_logs USING btree (billing_type);


--
-- Name: idx_usage_logs_created_at; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_usage_logs_created_at ON public.usage_logs USING btree (created_at);


--
-- Name: idx_usage_logs_group_id; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_usage_logs_group_id ON public.usage_logs USING btree (group_id);


--
-- Name: idx_usage_logs_ip_address; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_usage_logs_ip_address ON public.usage_logs USING btree (ip_address);


--
-- Name: idx_usage_logs_model; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_usage_logs_model ON public.usage_logs USING btree (model);


--
-- Name: idx_usage_logs_model_created_at; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_usage_logs_model_created_at ON public.usage_logs USING btree (model, created_at);


--
-- Name: idx_usage_logs_request_id_api_key_unique; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE UNIQUE INDEX idx_usage_logs_request_id_api_key_unique ON public.usage_logs USING btree (request_id, api_key_id);


--
-- Name: idx_usage_logs_sub_created; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_usage_logs_sub_created ON public.usage_logs USING btree (subscription_id, created_at);


--
-- Name: idx_usage_logs_subscription_id; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_usage_logs_subscription_id ON public.usage_logs USING btree (subscription_id);


--
-- Name: idx_usage_logs_user_created; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_usage_logs_user_created ON public.usage_logs USING btree (user_id, created_at);


--
-- Name: idx_usage_logs_user_id; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_usage_logs_user_id ON public.usage_logs USING btree (user_id);


--
-- Name: idx_user_allowed_groups_group_id; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_user_allowed_groups_group_id ON public.user_allowed_groups USING btree (group_id);


--
-- Name: idx_user_attribute_definitions_deleted_at; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_user_attribute_definitions_deleted_at ON public.user_attribute_definitions USING btree (deleted_at);


--
-- Name: idx_user_attribute_definitions_display_order; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_user_attribute_definitions_display_order ON public.user_attribute_definitions USING btree (display_order);


--
-- Name: idx_user_attribute_definitions_enabled; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_user_attribute_definitions_enabled ON public.user_attribute_definitions USING btree (enabled);


--
-- Name: idx_user_attribute_definitions_key_unique; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE UNIQUE INDEX idx_user_attribute_definitions_key_unique ON public.user_attribute_definitions USING btree (key) WHERE (deleted_at IS NULL);


--
-- Name: idx_user_attribute_values_attribute_id; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_user_attribute_values_attribute_id ON public.user_attribute_values USING btree (attribute_id);


--
-- Name: idx_user_attribute_values_user_id; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_user_attribute_values_user_id ON public.user_attribute_values USING btree (user_id);


--
-- Name: idx_user_group_rate_multipliers_group_id; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_user_group_rate_multipliers_group_id ON public.user_group_rate_multipliers USING btree (group_id);


--
-- Name: idx_user_ldap_profiles_active; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_user_ldap_profiles_active ON public.user_ldap_profiles USING btree (active);


--
-- Name: idx_user_ldap_profiles_ldap_uid; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE UNIQUE INDEX idx_user_ldap_profiles_ldap_uid ON public.user_ldap_profiles USING btree (ldap_uid);


--
-- Name: idx_user_subscriptions_assigned_by; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_user_subscriptions_assigned_by ON public.user_subscriptions USING btree (assigned_by);


--
-- Name: idx_user_subscriptions_expires_at; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_user_subscriptions_expires_at ON public.user_subscriptions USING btree (expires_at);


--
-- Name: idx_user_subscriptions_group_id; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_user_subscriptions_group_id ON public.user_subscriptions USING btree (group_id);


--
-- Name: idx_user_subscriptions_status; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_user_subscriptions_status ON public.user_subscriptions USING btree (status);


--
-- Name: idx_user_subscriptions_user_id; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_user_subscriptions_user_id ON public.user_subscriptions USING btree (user_id);


--
-- Name: idx_users_auth_source; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_users_auth_source ON public.users USING btree (auth_source) WHERE (deleted_at IS NULL);


--
-- Name: idx_users_deleted_at; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_users_deleted_at ON public.users USING btree (deleted_at);


--
-- Name: idx_users_status; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_users_status ON public.users USING btree (status);


--
-- Name: idx_users_token_version; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_users_token_version ON public.users USING btree (token_version) WHERE (deleted_at IS NULL);


--
-- Name: idx_users_totp_enabled; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX idx_users_totp_enabled ON public.users USING btree (totp_enabled) WHERE ((deleted_at IS NULL) AND (totp_enabled = true));


--
-- Name: user_subscriptions_user_group_unique_active; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE UNIQUE INDEX user_subscriptions_user_group_unique_active ON public.user_subscriptions USING btree (user_id, group_id) WHERE (deleted_at IS NULL);


--
-- Name: users_email_unique_active; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE UNIQUE INDEX users_email_unique_active ON public.users USING btree (email) WHERE (deleted_at IS NULL);


--
-- Name: usersubscription_deleted_at; Type: INDEX; Schema: public; Owner: sub2api
--

CREATE INDEX usersubscription_deleted_at ON public.user_subscriptions USING btree (deleted_at);


--
-- Name: account_groups account_groups_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.account_groups
    ADD CONSTRAINT account_groups_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: account_groups account_groups_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.account_groups
    ADD CONSTRAINT account_groups_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.groups(id) ON DELETE CASCADE;


--
-- Name: accounts accounts_proxy_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.accounts
    ADD CONSTRAINT accounts_proxy_id_fkey FOREIGN KEY (proxy_id) REFERENCES public.proxies(id) ON DELETE SET NULL;


--
-- Name: announcement_reads announcement_reads_announcement_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.announcement_reads
    ADD CONSTRAINT announcement_reads_announcement_id_fkey FOREIGN KEY (announcement_id) REFERENCES public.announcements(id) ON DELETE CASCADE;


--
-- Name: announcement_reads announcement_reads_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.announcement_reads
    ADD CONSTRAINT announcement_reads_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: announcements announcements_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.announcements
    ADD CONSTRAINT announcements_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: announcements announcements_updated_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.announcements
    ADD CONSTRAINT announcements_updated_by_fkey FOREIGN KEY (updated_by) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: api_keys api_keys_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT api_keys_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.groups(id) ON DELETE SET NULL;


--
-- Name: api_keys api_keys_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT api_keys_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: billing_usage_entries billing_usage_entries_api_key_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.billing_usage_entries
    ADD CONSTRAINT billing_usage_entries_api_key_id_fkey FOREIGN KEY (api_key_id) REFERENCES public.api_keys(id) ON DELETE CASCADE;


--
-- Name: billing_usage_entries billing_usage_entries_subscription_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.billing_usage_entries
    ADD CONSTRAINT billing_usage_entries_subscription_id_fkey FOREIGN KEY (subscription_id) REFERENCES public.user_subscriptions(id) ON DELETE SET NULL;


--
-- Name: billing_usage_entries billing_usage_entries_usage_log_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.billing_usage_entries
    ADD CONSTRAINT billing_usage_entries_usage_log_id_fkey FOREIGN KEY (usage_log_id) REFERENCES public.usage_logs(id) ON DELETE CASCADE;


--
-- Name: billing_usage_entries billing_usage_entries_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.billing_usage_entries
    ADD CONSTRAINT billing_usage_entries_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: sora_accounts fk_sora_accounts_account_id; Type: FK CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.sora_accounts
    ADD CONSTRAINT fk_sora_accounts_account_id FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: groups groups_fallback_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.groups
    ADD CONSTRAINT groups_fallback_group_id_fkey FOREIGN KEY (fallback_group_id) REFERENCES public.groups(id) ON DELETE SET NULL;


--
-- Name: groups groups_fallback_group_id_on_invalid_request_fkey; Type: FK CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.groups
    ADD CONSTRAINT groups_fallback_group_id_on_invalid_request_fkey FOREIGN KEY (fallback_group_id_on_invalid_request) REFERENCES public.groups(id) ON DELETE SET NULL;


--
-- Name: promo_code_usages promo_code_usages_promo_code_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.promo_code_usages
    ADD CONSTRAINT promo_code_usages_promo_code_id_fkey FOREIGN KEY (promo_code_id) REFERENCES public.promo_codes(id) ON DELETE CASCADE;


--
-- Name: promo_code_usages promo_code_usages_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.promo_code_usages
    ADD CONSTRAINT promo_code_usages_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: redeem_codes redeem_codes_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.redeem_codes
    ADD CONSTRAINT redeem_codes_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.groups(id) ON DELETE SET NULL;


--
-- Name: redeem_codes redeem_codes_used_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.redeem_codes
    ADD CONSTRAINT redeem_codes_used_by_fkey FOREIGN KEY (used_by) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: usage_cleanup_tasks usage_cleanup_tasks_canceled_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.usage_cleanup_tasks
    ADD CONSTRAINT usage_cleanup_tasks_canceled_by_fkey FOREIGN KEY (canceled_by) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: usage_cleanup_tasks usage_cleanup_tasks_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.usage_cleanup_tasks
    ADD CONSTRAINT usage_cleanup_tasks_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id) ON DELETE RESTRICT;


--
-- Name: usage_logs usage_logs_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.usage_logs
    ADD CONSTRAINT usage_logs_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: usage_logs usage_logs_api_key_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.usage_logs
    ADD CONSTRAINT usage_logs_api_key_id_fkey FOREIGN KEY (api_key_id) REFERENCES public.api_keys(id) ON DELETE CASCADE;


--
-- Name: usage_logs usage_logs_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.usage_logs
    ADD CONSTRAINT usage_logs_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.groups(id) ON DELETE SET NULL;


--
-- Name: usage_logs usage_logs_subscription_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.usage_logs
    ADD CONSTRAINT usage_logs_subscription_id_fkey FOREIGN KEY (subscription_id) REFERENCES public.user_subscriptions(id) ON DELETE SET NULL;


--
-- Name: usage_logs usage_logs_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.usage_logs
    ADD CONSTRAINT usage_logs_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: user_allowed_groups user_allowed_groups_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.user_allowed_groups
    ADD CONSTRAINT user_allowed_groups_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.groups(id) ON DELETE CASCADE;


--
-- Name: user_allowed_groups user_allowed_groups_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.user_allowed_groups
    ADD CONSTRAINT user_allowed_groups_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: user_attribute_values user_attribute_values_attribute_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.user_attribute_values
    ADD CONSTRAINT user_attribute_values_attribute_id_fkey FOREIGN KEY (attribute_id) REFERENCES public.user_attribute_definitions(id) ON DELETE CASCADE;


--
-- Name: user_attribute_values user_attribute_values_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.user_attribute_values
    ADD CONSTRAINT user_attribute_values_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: user_group_rate_multipliers user_group_rate_multipliers_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.user_group_rate_multipliers
    ADD CONSTRAINT user_group_rate_multipliers_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.groups(id) ON DELETE CASCADE;


--
-- Name: user_group_rate_multipliers user_group_rate_multipliers_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.user_group_rate_multipliers
    ADD CONSTRAINT user_group_rate_multipliers_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: user_ldap_profiles user_ldap_profiles_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.user_ldap_profiles
    ADD CONSTRAINT user_ldap_profiles_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: user_subscriptions user_subscriptions_assigned_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.user_subscriptions
    ADD CONSTRAINT user_subscriptions_assigned_by_fkey FOREIGN KEY (assigned_by) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: user_subscriptions user_subscriptions_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.user_subscriptions
    ADD CONSTRAINT user_subscriptions_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.groups(id) ON DELETE CASCADE;


--
-- Name: user_subscriptions user_subscriptions_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: sub2api
--

ALTER TABLE ONLY public.user_subscriptions
    ADD CONSTRAINT user_subscriptions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--

\unrestrict dcY5lihiQ45wmClxbFokv0KIPaSTantWz3k0LIraCLa1hemSIDtufmJcosJD3PM

