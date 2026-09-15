/**
 * Tailwind config for the Viche frontend.
 *
 * This replaces the `https://cdn.tailwindcss.com` play-CDN script that used to
 * sit in index.html alongside an inline `tailwind.config = {...}` block. That
 * CDN ships a runtime JIT compiler, which Tailwind explicitly documents as
 * not-for-production and which cannot coexist with a strict CSP (it builds and
 * injects stylesheets at runtime, and is a third-party script inside the page
 * that handles the voter's session).
 *
 * The `brand` palette below is carried over verbatim from that inline block —
 * same ten stops, same hex values.
 *
 * Content scanning covers the Rust sources because every class name in this
 * app lives inside a Leptos `view!` macro (`class="..."`), which is just a
 * string literal as far as Tailwind's extractor is concerned.
 */
module.exports = {
  content: [
    "./index.html",
    "./src/**/*.rs",
  ],
  theme: {
    extend: {
      colors: {
        brand: {
          50: "#f5f3ff",
          100: "#ede9fe",
          200: "#ddd6fe",
          300: "#c4b5fd",
          400: "#a78bfa",
          500: "#8b5cf6",
          600: "#7c3aed",
          700: "#6d28d9",
          800: "#5b21b6",
          900: "#4c1d95",
        },
      },
    },
  },
  // `poll_list.rs` builds a badge class list with `format!("... {}", classes)`
  // where `classes` is chosen from a fixed set of literals; those literals are
  // all present verbatim in the source, so the extractor finds them. If a
  // future component ever composes class names from fragments, add them here.
  safelist: [],
  plugins: [],
};
