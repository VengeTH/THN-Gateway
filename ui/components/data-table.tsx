/**
 * The responsive table.
 *
 * # Why this exists
 *
 * Every table in this console holds the same shape of data: a short set of
 * labels and a long explanatory value per row. That shape cannot survive a
 * 320px viewport as a table — four columns become four two-word columns, and
 * a condition like `network.inspect.supported && !network.wan.up` is chopped
 * into six lines of three characters.
 *
 * So the same data renders two ways:
 *
 *   - `sm` and up: a real `<table>`, because that is what a table is for.
 *   - below `sm`: a list of cards, one per row, where the first column is the
 *     heading and the rest become label/value pairs. A card wraps the way
 *     prose wraps, which is what the content already is.
 *
 * Only one of the two is ever in the accessibility tree at a time — CSS
 * `hidden` removes the other — so a screen reader is not offered a
 * table-shaped description of a list.
 *
 * The columns are declared once, as data, and both renderings read from that
 * one declaration. A column cannot drift between the two views because there
 * is only one place it is named.
 *
 * # Why this is a server component
 *
 * It takes `render` callbacks as props, and a function cannot cross the
 * server/client boundary. Marking this file `"use client"` would force every
 * page using it to become a client component and would serialise the whole
 * rule set into the RSC payload.
 *
 * It needs no client features: the responsive switch is two CSS breakpoints,
 * not state. Keeping it server-side means the table costs no JavaScript at
 * all, which is the correct outcome for a table.
 */

export interface Column<T> {
  /** Stable key, also used as the React key and the mobile label. */
  key: string;
  /** Human column heading. Shown in the table header and the card. */
  label: string;
  /**
   * Column width as a CSS grid template for the mobile card, e.g. `"1fr"` or
   * `"minmax(0,1fr)"`. Ignored by the table, which sizes itself.
   */
  width?: string;
  /** Optional extra classes on the `<td>` / card value cell. */
  className?: string;
  /** Hide this column on the mobile card — for values repeated in the header. */
  hideOnMobile?: boolean;
  render: (row: T, index: number) => React.ReactNode;
}

export interface DataTableProps<T> {
  columns: ReadonlyArray<Column<T>>;
  rows: ReadonlyArray<T>;
  /** Unique key per row. */
  rowKey: (row: T, index: number) => string;
  /** Shown instead of the table when there are no rows. */
  empty?: React.ReactNode;
  /** Accessible caption, and the fallback heading if the header is missing. */
  caption?: string;
  /** Highlight the first card, for "the answer is here". */
  emphasiseFirst?: boolean;
}

export function DataTable<T>({
  columns,
  rows,
  rowKey,
  empty,
  caption,
}: DataTableProps<T>) {
  if (rows.length === 0 && empty) {
    return <>{empty}</>;
  }

  // The mobile card leads with the first column, so it is pulled out of the
  // body and the rest are rendered as pairs beneath it. A table whose first
  // column is "severity" would otherwise head every card with the word
  // "critical", which is a category, not a title.
  const [lead, ...rest] = columns;

  return (
    <>
      {/*
        Wide screens: a table. `overflow-x-auto` rather than a forced
        `table-fixed`, because the fixed layout that used to be here gave
        every column the width the first row needed and then overflowed the
        last one off the edge of the panel.
      */}
      <div className="table-scroll">
        <table className="data-table">
          {caption ? <caption className="sr-only">{caption}</caption> : null}
          <thead>
            <tr>
              {columns.map((c) => (
                <th key={c.key} scope="col" className={`label ${c.className ?? ""}`}>
                  {c.label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((row, i) => (
              <tr key={rowKey(row, i)}>
                {columns.map((c) => (
                  <td key={c.key} className={c.className}>
                    {c.render(row, i)}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Narrow screens: one card per row. */}
      <ul className="divide-y divide-ink-850 sm:hidden">
        {rows.map((row, i) => (
          <li key={rowKey(row, i)} className="py-3 first:pt-0 last:pb-0">
            <div className="min-w-0">
              {lead ? <div className="mb-1">{lead.render(row, i)}</div> : null}
              <dl className="space-y-1">
                {rest
                  .filter((c) => !c.hideOnMobile)
                  .map((c) => (
                    <div key={c.key} className="grid grid-cols-[5.5rem_minmax(0,1fr)] gap-2">
                      <dt className="label pt-px">{c.label}</dt>
                      <dd className={`min-w-0 text-xs text-ink-200 ${c.className ?? ""}`}>
                        {c.render(row, i)}
                      </dd>
                    </div>
                  ))}
              </dl>
            </div>
          </li>
        ))}
      </ul>
    </>
  );
}