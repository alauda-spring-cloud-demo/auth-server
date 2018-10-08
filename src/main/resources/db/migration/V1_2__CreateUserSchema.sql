/**
UserInfo Schema
 */
create table `users`(
	id bigint unsigned NOT NULL PRIMARY KEY AUTO_INCREMENT,
	username VARCHAR(50) not null,
	password VARCHAR(60) not null,
	account_non_expired boolean not null DEFAULT true,
	credentials_non_expired boolean not null DEFAULT true,
	account_non_locked boolean not null DEFAULT true,
	enabled boolean not null DEFAULT true,
	avatar VARCHAR(1024) null,
	mail VARCHAR(128) null,
	phone VARCHAR(50) null,
	display_name VARCHAR(50) null
);

create unique index ix_users_username on `users` (username);

create table authorities (
	id bigint unsigned NOT NULL PRIMARY KEY AUTO_INCREMENT,
	username VARCHAR(50) NOT NULL,
	authority VARCHAR(50) not null,
	constraint fk_authorities_users foreign key(username) references users(username)
);

create unique index ix_authorities_authority_username on authorities (authority,username);

/**
Group Authorities
 */
create table `groups` (
	id bigint unsigned NOT NULL PRIMARY KEY AUTO_INCREMENT,
	group_name VARCHAR(50) not null
);

create unique index ix_groups_group_name on `groups` (group_name);

create table group_authorities (
	id bigint unsigned NOT NULL PRIMARY KEY AUTO_INCREMENT,
	group_id bigint unsigned not null,
	authority VARCHAR(50) not null,
	constraint fk_group_authorities_group foreign key(group_id) references `groups`(id)
);

create table group_members (
	id bigint unsigned NOT NULL PRIMARY KEY AUTO_INCREMENT,
	user_id bigint unsigned not null,
	username VARCHAR(50) NOT NULL,
	group_id bigint unsigned not null,
	constraint fk_group_members_group foreign key(group_id) references `groups`(id),
	constraint fk_group_members_user foreign key(user_id) references `users`(id)
);

/**
Persistent Token Approach(RememberMe)
 */
create table persistent_logins (
	username VARCHAR(64) not null,
	series VARCHAR(64) primary key,
	token VARCHAR(64) not null,
	last_used timestamp not null
);