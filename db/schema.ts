import { sqliteTable, text, integer, index } from 'drizzle-orm/sqlite-core';
export const accounts = sqliteTable('accounts', { id:text('id').primaryKey(), alias:text('alias').notNull(), created:text('created').notNull() });
export const keys = sqliteTable('passkeys', {
 id:text('id').primaryKey(), owner:text('owner').notNull().references(()=>accounts.id), publicKey:text('public_key').notNull(),
 counter:integer('counter').notNull(), name:text('name').notNull(), provider:text('provider').notNull(), transports:text('transports').notNull(), created:text('created').notNull(),
}, t=>[index('keys_owner').on(t.owner)]);
export const sessions = sqliteTable('sessions', {
 hash:text('hash').primaryKey(), owner:text('owner').notNull().references(()=>accounts.id), credential:text('credential').notNull().references(()=>keys.id,{onDelete:'cascade'}), expires:integer('expires').notNull(), authenticated:integer('authenticated').notNull(),
}, t=>[index('sessions_owner').on(t.owner)]);
export const challenges = sqliteTable('challenges', {
 id:text('id').primaryKey(), browser:text('browser').notNull(), kind:text('kind').notNull(), value:text('value').notNull(), payload:text('payload').notNull(), expires:integer('expires').notNull(),
}, t=>[index('challenges_browser').on(t.browser),index('challenges_expiry').on(t.expires)]);
export const notes = sqliteTable('notes', { id:text('id').primaryKey(), owner:text('owner').notNull().references(()=>accounts.id), title:text('title').notNull(), body:text('body').notNull() },t=>[index('notes_owner').on(t.owner)]);
