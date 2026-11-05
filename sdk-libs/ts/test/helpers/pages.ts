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
