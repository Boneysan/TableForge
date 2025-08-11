CREATE TABLE "board_assets" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"room_id" varchar NOT NULL,
	"asset_id" varchar NOT NULL,
	"position_x" integer NOT NULL,
	"position_y" integer NOT NULL,
	"rotation" integer DEFAULT 0 NOT NULL,
	"scale" integer DEFAULT 100 NOT NULL,
	"is_flipped" boolean DEFAULT false NOT NULL,
	"z_index" integer DEFAULT 0 NOT NULL,
	"owned_by" varchar,
	"visibility" varchar DEFAULT 'public',
	"asset_type" varchar DEFAULT 'other',
	"face_down" boolean DEFAULT false,
	"stack_order" integer DEFAULT 0,
	"snap_to_grid" boolean DEFAULT false,
	"is_locked" boolean DEFAULT false,
	"placed_at" timestamp DEFAULT now(),
	"placed_by" varchar
);
--> statement-breakpoint
CREATE TABLE "card_decks" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"room_id" varchar NOT NULL,
	"name" varchar(100) NOT NULL,
	"description" text,
	"created_by" varchar NOT NULL,
	"is_shuffled" boolean DEFAULT false,
	"deck_order" json,
	"theme" json,
	"card_back_asset_id" varchar,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "card_piles" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"room_id" varchar NOT NULL,
	"name" varchar(100) NOT NULL,
	"position_x" integer NOT NULL,
	"position_y" integer NOT NULL,
	"pile_type" varchar DEFAULT 'custom',
	"visibility" varchar DEFAULT 'public',
	"owner_id" varchar,
	"card_order" json,
	"face_down" boolean DEFAULT false,
	"max_cards" integer,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "chat_messages" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"room_id" varchar NOT NULL,
	"player_id" varchar NOT NULL,
	"message" varchar(1000) NOT NULL,
	"message_type" varchar DEFAULT 'chat' NOT NULL,
	"target_player_id" varchar,
	"sent_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "dice_rolls" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"room_id" varchar NOT NULL,
	"player_id" varchar NOT NULL,
	"dice_type" text NOT NULL,
	"dice_count" integer NOT NULL,
	"results" json NOT NULL,
	"total" integer NOT NULL,
	"rolled_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "game_assets" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"room_id" varchar,
	"system_id" varchar,
	"name" text NOT NULL,
	"type" text NOT NULL,
	"file_path" text NOT NULL,
	"width" integer,
	"height" integer,
	"uploaded_by" varchar NOT NULL,
	"is_system_asset" boolean DEFAULT false NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "game_rooms" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" text NOT NULL,
	"created_by" varchar NOT NULL,
	"is_active" boolean DEFAULT true NOT NULL,
	"game_state" json,
	"board_width" integer DEFAULT 800 NOT NULL,
	"board_height" integer DEFAULT 600 NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	CONSTRAINT "game_rooms_name_unique" UNIQUE("name")
);
--> statement-breakpoint
CREATE TABLE "game_systems" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" varchar(255) NOT NULL,
	"description" text,
	"created_by" varchar,
	"is_public" boolean DEFAULT false,
	"category" varchar(100),
	"tags" text[],
	"thumbnail_url" varchar,
	"system_config" jsonb,
	"asset_library" jsonb,
	"deck_templates" jsonb,
	"token_types" jsonb,
	"board_defaults" jsonb,
	"version" varchar(20) DEFAULT '1.0',
	"is_official" boolean DEFAULT false,
	"complexity" varchar(20) DEFAULT 'medium',
	"download_count" integer DEFAULT 0,
	"rating" numeric(3, 2),
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "game_templates" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" varchar(255) NOT NULL,
	"description" text,
	"created_by" varchar,
	"is_public" boolean DEFAULT false,
	"category" varchar(100),
	"tags" text[],
	"thumbnail_url" varchar,
	"board_config" jsonb,
	"decks_data" jsonb,
	"tokens_data" jsonb,
	"assets_data" jsonb,
	"players_min" integer DEFAULT 1,
	"players_max" integer DEFAULT 8,
	"estimated_duration" varchar,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "room_players" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"room_id" varchar NOT NULL,
	"player_id" varchar NOT NULL,
	"role" text DEFAULT 'player' NOT NULL,
	"is_online" boolean DEFAULT true NOT NULL,
	"score" integer DEFAULT 0 NOT NULL,
	"joined_at" timestamp DEFAULT now() NOT NULL,
	CONSTRAINT "room_players_room_id_player_id_unique" UNIQUE("room_id","player_id")
);
--> statement-breakpoint
CREATE TABLE "sessions" (
	"sid" varchar PRIMARY KEY NOT NULL,
	"sess" jsonb NOT NULL,
	"expire" timestamp NOT NULL
);
--> statement-breakpoint
CREATE TABLE "template_usage" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"template_id" varchar,
	"room_id" varchar,
	"used_by" varchar,
	"used_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "users" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"email" varchar,
	"first_name" varchar,
	"last_name" varchar,
	"profile_image_url" varchar,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now(),
	CONSTRAINT "users_email_unique" UNIQUE("email")
);
--> statement-breakpoint
ALTER TABLE "board_assets" ADD CONSTRAINT "board_assets_room_id_game_rooms_id_fk" FOREIGN KEY ("room_id") REFERENCES "public"."game_rooms"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "board_assets" ADD CONSTRAINT "board_assets_asset_id_game_assets_id_fk" FOREIGN KEY ("asset_id") REFERENCES "public"."game_assets"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "board_assets" ADD CONSTRAINT "board_assets_owned_by_users_id_fk" FOREIGN KEY ("owned_by") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "board_assets" ADD CONSTRAINT "board_assets_placed_by_users_id_fk" FOREIGN KEY ("placed_by") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "card_decks" ADD CONSTRAINT "card_decks_room_id_game_rooms_id_fk" FOREIGN KEY ("room_id") REFERENCES "public"."game_rooms"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "card_decks" ADD CONSTRAINT "card_decks_created_by_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "card_decks" ADD CONSTRAINT "card_decks_card_back_asset_id_game_assets_id_fk" FOREIGN KEY ("card_back_asset_id") REFERENCES "public"."game_assets"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "card_piles" ADD CONSTRAINT "card_piles_room_id_game_rooms_id_fk" FOREIGN KEY ("room_id") REFERENCES "public"."game_rooms"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "card_piles" ADD CONSTRAINT "card_piles_owner_id_users_id_fk" FOREIGN KEY ("owner_id") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "chat_messages" ADD CONSTRAINT "chat_messages_room_id_game_rooms_id_fk" FOREIGN KEY ("room_id") REFERENCES "public"."game_rooms"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "chat_messages" ADD CONSTRAINT "chat_messages_player_id_users_id_fk" FOREIGN KEY ("player_id") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "chat_messages" ADD CONSTRAINT "chat_messages_target_player_id_users_id_fk" FOREIGN KEY ("target_player_id") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "dice_rolls" ADD CONSTRAINT "dice_rolls_room_id_game_rooms_id_fk" FOREIGN KEY ("room_id") REFERENCES "public"."game_rooms"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "dice_rolls" ADD CONSTRAINT "dice_rolls_player_id_users_id_fk" FOREIGN KEY ("player_id") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "game_assets" ADD CONSTRAINT "game_assets_room_id_game_rooms_id_fk" FOREIGN KEY ("room_id") REFERENCES "public"."game_rooms"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "game_assets" ADD CONSTRAINT "game_assets_system_id_game_systems_id_fk" FOREIGN KEY ("system_id") REFERENCES "public"."game_systems"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "game_assets" ADD CONSTRAINT "game_assets_uploaded_by_users_id_fk" FOREIGN KEY ("uploaded_by") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "game_rooms" ADD CONSTRAINT "game_rooms_created_by_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "game_systems" ADD CONSTRAINT "game_systems_created_by_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "game_templates" ADD CONSTRAINT "game_templates_created_by_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "room_players" ADD CONSTRAINT "room_players_room_id_game_rooms_id_fk" FOREIGN KEY ("room_id") REFERENCES "public"."game_rooms"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "room_players" ADD CONSTRAINT "room_players_player_id_users_id_fk" FOREIGN KEY ("player_id") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "template_usage" ADD CONSTRAINT "template_usage_template_id_game_templates_id_fk" FOREIGN KEY ("template_id") REFERENCES "public"."game_templates"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "template_usage" ADD CONSTRAINT "template_usage_room_id_game_rooms_id_fk" FOREIGN KEY ("room_id") REFERENCES "public"."game_rooms"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "template_usage" ADD CONSTRAINT "template_usage_used_by_users_id_fk" FOREIGN KEY ("used_by") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "idx_board_assets_room_id" ON "board_assets" USING btree ("room_id");--> statement-breakpoint
CREATE INDEX "idx_board_assets_asset_id" ON "board_assets" USING btree ("asset_id");--> statement-breakpoint
CREATE INDEX "idx_board_assets_owned_by" ON "board_assets" USING btree ("owned_by");--> statement-breakpoint
CREATE INDEX "idx_board_assets_placed_by" ON "board_assets" USING btree ("placed_by");--> statement-breakpoint
CREATE INDEX "idx_board_assets_asset_type" ON "board_assets" USING btree ("asset_type");--> statement-breakpoint
CREATE INDEX "idx_board_assets_visibility" ON "board_assets" USING btree ("visibility");--> statement-breakpoint
CREATE INDEX "idx_board_assets_z_index" ON "board_assets" USING btree ("z_index");--> statement-breakpoint
CREATE INDEX "idx_board_assets_placed_at" ON "board_assets" USING btree ("placed_at");--> statement-breakpoint
CREATE INDEX "idx_board_assets_room_position" ON "board_assets" USING btree ("room_id","position_x","position_y");--> statement-breakpoint
CREATE INDEX "idx_board_assets_room_z_order" ON "board_assets" USING btree ("room_id","z_index");--> statement-breakpoint
CREATE INDEX "idx_board_assets_stack_order" ON "board_assets" USING btree ("room_id","stack_order");--> statement-breakpoint
CREATE INDEX "idx_card_decks_room_id" ON "card_decks" USING btree ("room_id");--> statement-breakpoint
CREATE INDEX "idx_card_decks_created_by" ON "card_decks" USING btree ("created_by");--> statement-breakpoint
CREATE INDEX "idx_card_decks_card_back_asset_id" ON "card_decks" USING btree ("card_back_asset_id");--> statement-breakpoint
CREATE INDEX "idx_card_decks_created_at" ON "card_decks" USING btree ("created_at");--> statement-breakpoint
CREATE INDEX "idx_card_piles_room_id" ON "card_piles" USING btree ("room_id");--> statement-breakpoint
CREATE INDEX "idx_card_piles_owner_id" ON "card_piles" USING btree ("owner_id");--> statement-breakpoint
CREATE INDEX "idx_card_piles_pile_type" ON "card_piles" USING btree ("pile_type");--> statement-breakpoint
CREATE INDEX "idx_card_piles_visibility" ON "card_piles" USING btree ("visibility");--> statement-breakpoint
CREATE INDEX "idx_card_piles_created_at" ON "card_piles" USING btree ("created_at");--> statement-breakpoint
CREATE INDEX "idx_card_piles_room_position" ON "card_piles" USING btree ("room_id","position_x","position_y");--> statement-breakpoint
CREATE INDEX "idx_card_piles_room_type" ON "card_piles" USING btree ("room_id","pile_type");--> statement-breakpoint
CREATE INDEX "idx_chat_messages_room_id" ON "chat_messages" USING btree ("room_id");--> statement-breakpoint
CREATE INDEX "idx_chat_messages_player_id" ON "chat_messages" USING btree ("player_id");--> statement-breakpoint
CREATE INDEX "idx_chat_messages_target_player_id" ON "chat_messages" USING btree ("target_player_id");--> statement-breakpoint
CREATE INDEX "idx_chat_messages_message_type" ON "chat_messages" USING btree ("message_type");--> statement-breakpoint
CREATE INDEX "idx_chat_messages_sent_at" ON "chat_messages" USING btree ("sent_at");--> statement-breakpoint
CREATE INDEX "idx_chat_messages_room_sent_at" ON "chat_messages" USING btree ("room_id","sent_at");--> statement-breakpoint
CREATE INDEX "idx_dice_rolls_room_id" ON "dice_rolls" USING btree ("room_id");--> statement-breakpoint
CREATE INDEX "idx_dice_rolls_player_id" ON "dice_rolls" USING btree ("player_id");--> statement-breakpoint
CREATE INDEX "idx_dice_rolls_rolled_at" ON "dice_rolls" USING btree ("rolled_at");--> statement-breakpoint
CREATE INDEX "idx_dice_rolls_room_rolled_at" ON "dice_rolls" USING btree ("room_id","rolled_at");--> statement-breakpoint
CREATE INDEX "idx_game_assets_room_id" ON "game_assets" USING btree ("room_id");--> statement-breakpoint
CREATE INDEX "idx_game_assets_system_id" ON "game_assets" USING btree ("system_id");--> statement-breakpoint
CREATE INDEX "idx_game_assets_uploaded_by" ON "game_assets" USING btree ("uploaded_by");--> statement-breakpoint
CREATE INDEX "idx_game_assets_type" ON "game_assets" USING btree ("type");--> statement-breakpoint
CREATE INDEX "idx_game_assets_is_system_asset" ON "game_assets" USING btree ("is_system_asset");--> statement-breakpoint
CREATE INDEX "idx_game_assets_created_at" ON "game_assets" USING btree ("created_at");--> statement-breakpoint
CREATE INDEX "idx_game_assets_room_type" ON "game_assets" USING btree ("room_id","type");--> statement-breakpoint
CREATE INDEX "idx_game_assets_system_type" ON "game_assets" USING btree ("system_id","type");--> statement-breakpoint
CREATE INDEX "idx_game_rooms_created_by" ON "game_rooms" USING btree ("created_by");--> statement-breakpoint
CREATE INDEX "idx_game_rooms_is_active" ON "game_rooms" USING btree ("is_active");--> statement-breakpoint
CREATE INDEX "idx_game_rooms_created_at" ON "game_rooms" USING btree ("created_at");--> statement-breakpoint
CREATE INDEX "idx_game_systems_created_by" ON "game_systems" USING btree ("created_by");--> statement-breakpoint
CREATE INDEX "idx_game_systems_is_public" ON "game_systems" USING btree ("is_public");--> statement-breakpoint
CREATE INDEX "idx_game_systems_is_official" ON "game_systems" USING btree ("is_official");--> statement-breakpoint
CREATE INDEX "idx_game_systems_category" ON "game_systems" USING btree ("category");--> statement-breakpoint
CREATE INDEX "idx_game_systems_complexity" ON "game_systems" USING btree ("complexity");--> statement-breakpoint
CREATE INDEX "idx_game_systems_download_count" ON "game_systems" USING btree ("download_count");--> statement-breakpoint
CREATE INDEX "idx_game_systems_rating" ON "game_systems" USING btree ("rating");--> statement-breakpoint
CREATE INDEX "idx_game_systems_created_at" ON "game_systems" USING btree ("created_at");--> statement-breakpoint
CREATE INDEX "idx_game_systems_updated_at" ON "game_systems" USING btree ("updated_at");--> statement-breakpoint
CREATE INDEX "idx_game_systems_public_category" ON "game_systems" USING btree ("is_public","category");--> statement-breakpoint
CREATE INDEX "idx_game_systems_public_official" ON "game_systems" USING btree ("is_public","is_official");--> statement-breakpoint
CREATE INDEX "idx_game_systems_public_rating" ON "game_systems" USING btree ("is_public","rating");--> statement-breakpoint
CREATE INDEX "idx_game_templates_created_by" ON "game_templates" USING btree ("created_by");--> statement-breakpoint
CREATE INDEX "idx_game_templates_is_public" ON "game_templates" USING btree ("is_public");--> statement-breakpoint
CREATE INDEX "idx_game_templates_category" ON "game_templates" USING btree ("category");--> statement-breakpoint
CREATE INDEX "idx_game_templates_created_at" ON "game_templates" USING btree ("created_at");--> statement-breakpoint
CREATE INDEX "idx_game_templates_updated_at" ON "game_templates" USING btree ("updated_at");--> statement-breakpoint
CREATE INDEX "idx_game_templates_public_category" ON "game_templates" USING btree ("is_public","category");--> statement-breakpoint
CREATE INDEX "idx_game_templates_public_created" ON "game_templates" USING btree ("is_public","created_at");--> statement-breakpoint
CREATE INDEX "idx_room_players_room_id" ON "room_players" USING btree ("room_id");--> statement-breakpoint
CREATE INDEX "idx_room_players_player_id" ON "room_players" USING btree ("player_id");--> statement-breakpoint
CREATE INDEX "idx_room_players_role" ON "room_players" USING btree ("role");--> statement-breakpoint
CREATE INDEX "idx_room_players_is_online" ON "room_players" USING btree ("is_online");--> statement-breakpoint
CREATE INDEX "idx_room_players_joined_at" ON "room_players" USING btree ("joined_at");--> statement-breakpoint
CREATE INDEX "IDX_session_expire" ON "sessions" USING btree ("expire");