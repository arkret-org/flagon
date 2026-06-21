macro_rules! impl_pg_enum {
    ($ty:ty, $sql_ty:path, {$($variant:path => $wire:literal),+ $(,)?}) => {
        impl $ty {
            pub fn as_pg(self) -> &'static str {
                match self {
                    $($variant => $wire,)+
                }
            }

            pub fn from_pg(value: &str) -> anyhow::Result<Self> {
                Ok(match value {
                    $($wire => $variant,)+
                    other => anyhow::bail!("unknown PostgreSQL enum value `{other}`"),
                })
            }
        }

        impl diesel::serialize::ToSql<$sql_ty, diesel::pg::Pg> for $ty {
            fn to_sql<'b>(
                &'b self,
                out: &mut diesel::serialize::Output<'b, '_, diesel::pg::Pg>,
            ) -> diesel::serialize::Result {
                use std::io::Write;

                out.write_all(self.as_pg().as_bytes())?;
                Ok(diesel::serialize::IsNull::No)
            }
        }

        impl diesel::deserialize::FromSql<$sql_ty, diesel::pg::Pg> for $ty {
            fn from_sql(
                bytes: diesel::pg::PgValue<'_>,
            ) -> diesel::deserialize::Result<Self> {
                let value = std::str::from_utf8(bytes.as_bytes())?;
                Self::from_pg(value).map_err(Into::into)
            }
        }
    };
}

pub(crate) use impl_pg_enum;
