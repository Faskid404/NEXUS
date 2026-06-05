import { pgTable, serial, text, integer, timestamp } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";

export const injectionLogsTable = pgTable("injection_logs", {
  id: serial("id").primaryKey(),
  timestamp: timestamp("timestamp", { withTimezone: true }).defaultNow().notNull(),
  command: text("command").notNull(),
  engine: text("engine").notNull(),
  mode: text("mode").notNull(),
  responseTime: integer("response_time").notNull(),
});

export const insertInjectionLogSchema = createInsertSchema(injectionLogsTable).omit({ id: true, timestamp: true });
export type InsertInjectionLog = z.infer<typeof insertInjectionLogSchema>;
export type InjectionLog = typeof injectionLogsTable.$inferSelect;
