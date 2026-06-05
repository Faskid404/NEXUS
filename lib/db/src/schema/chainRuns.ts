import { pgTable, serial, text, boolean, integer, timestamp } from "drizzle-orm/pg-core";

export const chainRunsTable = pgTable("chain_runs", {
  id:            serial("id").primaryKey(),
  timestamp:     timestamp("timestamp", { withTimezone: true }).defaultNow().notNull(),
  targetUrl:     text("target_url").notNull(),
  injectParam:   text("inject_param").notNull(),
  httpMethod:    text("http_method").notNull(),
  cmd:           text("cmd").notNull(),
  confirmed:     boolean("confirmed").notNull().default(false),
  confirmedMode: text("confirmed_mode"),
  confirmedVia:  text("confirmed_via"),
  exfilData:     text("exfil_data").notNull().default(""),
  elapsed:       integer("elapsed").notNull(),
  modesRun:      integer("modes_run").notNull(),
  totalModes:    integer("total_modes").notNull(),
  oobToken:      text("oob_token").notNull(),
});

export type ChainRunRow = typeof chainRunsTable.$inferSelect;
