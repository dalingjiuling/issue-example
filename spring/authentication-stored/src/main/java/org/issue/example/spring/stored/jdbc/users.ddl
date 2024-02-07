create table users(
  username VARCHAR(128) not null primary key,
  password VARCHAR(128) not null,
  enabled boolean not null
);

create table authorities (
 username VARCHAR(128) not null,
 authority VARCHAR(128) not null
);