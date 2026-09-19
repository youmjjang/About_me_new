CREATE TABLE `accounts` (
	`id` text PRIMARY KEY NOT NULL,
	`alias` text NOT NULL,
	`created` text NOT NULL
);
--> statement-breakpoint
CREATE TABLE `challenges` (
	`id` text PRIMARY KEY NOT NULL,
	`browser` text NOT NULL,
	`kind` text NOT NULL,
	`value` text NOT NULL,
	`payload` text NOT NULL,
	`expires` integer NOT NULL
);
--> statement-breakpoint
CREATE INDEX `challenges_browser` ON `challenges` (`browser`);--> statement-breakpoint
CREATE INDEX `challenges_expiry` ON `challenges` (`expires`);--> statement-breakpoint
CREATE TABLE `passkeys` (
	`id` text PRIMARY KEY NOT NULL,
	`owner` text NOT NULL,
	`public_key` text NOT NULL,
	`counter` integer NOT NULL,
	`name` text NOT NULL,
	`provider` text NOT NULL,
	`transports` text NOT NULL,
	`created` text NOT NULL,
	FOREIGN KEY (`owner`) REFERENCES `accounts`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE INDEX `keys_owner` ON `passkeys` (`owner`);--> statement-breakpoint
CREATE TABLE `notes` (
	`id` text PRIMARY KEY NOT NULL,
	`owner` text NOT NULL,
	`title` text NOT NULL,
	`body` text NOT NULL,
	FOREIGN KEY (`owner`) REFERENCES `accounts`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE INDEX `notes_owner` ON `notes` (`owner`);--> statement-breakpoint
CREATE TABLE `sessions` (
	`hash` text PRIMARY KEY NOT NULL,
	`owner` text NOT NULL,
	`credential` text NOT NULL,
	`expires` integer NOT NULL,
	`authenticated` integer NOT NULL,
	FOREIGN KEY (`owner`) REFERENCES `accounts`(`id`) ON UPDATE no action ON DELETE no action,
	FOREIGN KEY (`credential`) REFERENCES `passkeys`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `sessions_owner` ON `sessions` (`owner`);