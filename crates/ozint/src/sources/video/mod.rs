//! `entity-video (VID)` — the video-node tools: [`local_probe`] for a video already in the
//! local media store, and four platform lookups — [`youtube`], [`telegram`], [`bluesky`],
//! [`ytdlp`] (TikTok) — for a video identified by its post URL instead. See `plans::video_plan`
//! for why all five fire in one unconditional phase despite consuming four different value
//! shapes, and `outcome::ToolOutcome::SkippedNotApplicable` for how a tool declines the shapes
//! it doesn't consume.

pub mod bluesky;
pub mod local_probe;
pub mod telegram;
pub mod youtube;
pub mod ytdlp;
