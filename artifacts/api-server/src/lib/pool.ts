export class Pool {
  private running = 0;
  private readonly queue: Array<() => void> = [];

  constructor(readonly limit: number = 16) {}

  run<T>(fn: () => Promise<T>): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      const exec = () => {
        this.running++;
        fn().then(resolve, reject).finally(() => {
          this.running--;
          this.queue.shift()?.();
        });
      };
      if (this.running < this.limit) exec();
      else this.queue.push(exec);
    });
  }

  map<T, R>(items: T[], fn: (item: T, i: number) => Promise<R>): Promise<R[]> {
    return Promise.all(items.map((item, i) => this.run(() => fn(item, i))));
  }

  get active(): number { return this.running; }
  get queued(): number { return this.queue.length; }
}

export const globalPool = new Pool(16);
