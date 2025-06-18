/*
* Copyright (c) 2025 A Large Red Robot (rstat1@alargerobot.dev)
*
* Use of this source code is governed by a "BSD-style" license that can be
* found in the included LICENSE file.
*/

use crate::{data::CacheService, SYSTEM_CONFIG};

use redis::Commands;
use serde::Serialize;
use tracing::error;

impl CacheService {
	pub fn new() -> Result<Self, String> {
		let redisClient = match redis::Client::open(format!("redis://{}", SYSTEM_CONFIG.redisServerAddress)) {
			Ok(c) => c,
			Err(e) => {
				error!("error connecting to redis: {e}");
				return Err("Failed to connect to Redis".to_string());
			}
		};
		Ok(Self { redis: redisClient })
	}

	pub fn ReadStringFromRedis(&self, key: String) -> Result<String, String> {
		match self.redis.get_connection() {
			Ok(mut conn) => {
				let result: redis::RedisResult<String> = conn.get(key);
				match result {
					Ok(v) => Ok(v),
					Err(e) => Err(format!("ReadStringFromRedis: {e}")),
				}
			}
			Err(e) => Err(e.to_string()),
		}
	}
	pub fn WriteStringToRedis(&self, key: &String, value: &String) -> Result<bool, String> {
		match self.redis.get_connection() {
			Ok(mut conn) => {
				let result: redis::RedisResult<()> = conn.set(key, value);
				match result {
					Ok(_) => Ok(true),
					Err(e) => Err(format!("WriteStringToRedis: {e}")),
				}
			}
			Err(e) => Err(e.to_string()),
		}
	}
	pub fn WriteStringToRedisWithTTL(&self, key: &String, value: &String, ttl: u64) -> Result<bool, String> {
		match self.redis.get_connection() {
			Ok(mut conn) => {
				let result: redis::RedisResult<()> = conn.set_ex(key, value, ttl);
				match result {
					Ok(_) => Ok(true),
					Err(e) => Err(format!("WriteStringToRedisWithTTL: {e}")),
				}
			}
			Err(e) => Err(e.to_string()),
		}
	}
	pub fn AddObjectToList<T: Serialize>(&self, listName: &str, value: &T) -> Result<bool, String> {
		match self.redis.get_connection() {
			Ok(mut conn) => {
				let valueJson = value.serialize(serde_json::value::Serializer).map_err(|e| String::from(e.to_string()))?;
				let result: redis::RedisResult<()> = conn.lpush(listName, valueJson.to_string());
				match result {
					Ok(_) => Ok(true),
					Err(e) => Err(format!("AddObjectToList: {e}")),
				}
			}
			Err(_) => todo!(),
		}
	}
}
