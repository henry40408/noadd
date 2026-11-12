//! maud views for the server-rendered admin pages.
//!
//! A child of `pages`, so a view reads its page struct's private fields directly.
//! One function per page: `render(&page) -> Markup`. The shared document and
//! signed-in shell live in `layout`.

pub mod account;
pub mod auth;
pub mod dashboard;
pub mod filters;
pub mod layout;
pub mod logs;
pub mod registry;
pub mod settings;
pub mod stats;
