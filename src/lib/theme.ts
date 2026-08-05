export const THEME_STORAGE_KEY = "flexvault-theme";

export function toggleTheme() {
  const root = document.documentElement;
  const next = root.classList.contains("dark") ? "light" : "dark";
  root.classList.toggle("dark", next === "dark");
  root.style.colorScheme = next;
  window.localStorage.setItem(THEME_STORAGE_KEY, next);
}
