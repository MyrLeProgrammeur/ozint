import { OzintView } from "@/components/ozint/OzintView";

/**
 * The whole application. OZINT is one cockpit, not a set of pages, so there is no router
 * here and no shell around it — `OzintView` owns the full viewport.
 *
 * `onClose` is deliberately not passed: standalone, there is nothing behind the cockpit to
 * return to, and `OzintView` hides its close button when no handler is given.
 */
export function App() {
  return <OzintView />;
}
