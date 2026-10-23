type Event = { readonly slot: number | bigint; readonly txSignature: string };

export function transactionItems<T extends Event>(events: readonly T[]) {
  const items: { slot: T["slot"]; signature: T["txSignature"]; events: T[] }[] = [];
  for (const event of events) {
    let item = items.find(
      (item) => item.slot === event.slot && item.signature === event.txSignature,
    );
    if (item === undefined) {
      item = { slot: event.slot, signature: event.txSignature, events: [] };
      items.push(item);
    }
    item.events.push(event);
  }
  return items;
}

export function outputItems<T extends Event>(outputs: readonly T[]) {
  return transactionItems(outputs).map(({ events, ...header }) => ({ ...header, outputs: events }));
}

export function ringPage<C, T extends Event, S extends Event>(input: {
  context: C;
  value: { items: readonly T[]; skipped: readonly S[]; next?: string };
}) {
  const groups: { slot: number | bigint; signature: string; events: T[]; skipped: S[] }[] = [];
  for (const event of input.value.items) {
    let group = groups.find(
      (group) => group.slot === event.slot && group.signature === event.txSignature,
    );
    if (group === undefined) {
      group = { slot: event.slot, signature: event.txSignature, events: [], skipped: [] };
      groups.push(group);
    }
    group.events.push(event);
  }
  for (const event of input.value.skipped) {
    let group = groups.find(
      (group) => group.slot === event.slot && group.signature === event.txSignature,
    );
    if (group === undefined) {
      group = { slot: event.slot, signature: event.txSignature, events: [], skipped: [] };
      groups.push(group);
    }
    group.skipped.push(event);
  }
  groups.sort((a, b) => (a.slot < b.slot ? -1 : a.slot > b.slot ? 1 : 0));
  return { context: input.context, items: groups, paginationToken: input.value.next ?? null };
}
