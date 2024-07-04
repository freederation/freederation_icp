use serde::de::DeserializeOwned;
use serde::Serialize;/// JSON util


pub trait JsonUtil: Sized + Serialize + DeserializeOwned
where
    <Self as JsonUtil>::Err: From<serde_json::Error>,
{
    /// Error
    type Err;

    /// Deserialize JSON
    #[inline]
    fn from_json<T>(json: T) -> Result<Self, Self::Err>
    where
        T: AsRef<[u8]>,
    {
        Ok(serde_json::from_slice(json.as_ref())?)
    }

    /// Serialize to JSON string
    ///
    /// This method could panic! Use `try_as_json` for error propagation.
    #[inline]
    fn as_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }

    /// Serialize to JSON string
    #[inline]
    fn try_as_json(&self) -> Result<String, Self::Err> {
        Ok(serde_json::to_string(self)?)
    }
}