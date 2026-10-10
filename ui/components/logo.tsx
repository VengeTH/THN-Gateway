/**
 * The Heedful Official Logo Mark: V4 Hexagonal Eye
 *
 * Represents:
 * - Precision
 * - Machine awareness
 * - System intelligence
 * - Focused execution
 *
 * Designed with a geometric hexagon perimeter, concentric telemetry eye contours,
 * and a focused central core.
 */
export function HexagonalEyeLogo({
  className = "h-8 w-8",
}: {
  className?: string;
}) {
  return (
    <svg
      viewBox="0 0 32 32"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
      aria-hidden="true"
    >
      {/* Outer Hexagon */}
      <polygon
        points="16,2 29,9.5 29,24.5 16,32 3,24.5 3,9.5"
        className="fill-ink-900 stroke-accent"
        strokeWidth="1.75"
        strokeLinejoin="round"
      />

      {/* Internal Geometry & Eye Contours */}
      <path
        d="M8 17C10.5 12 21.5 12 24 17C21.5 22 10.5 22 8 17Z"
        className="stroke-accent"
        strokeWidth="1.5"
        strokeLinejoin="round"
      />

      {/* Central Core / Machine Pupil */}
      <circle cx="16" cy="17" r="2.75" className="fill-accent" />
    </svg>
  );
}