use oauth2::{AccessToken, RefreshToken};
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter};
use std::mem;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub type SecretString = Secret<String>;

#[derive(Clone, Zeroize, ZeroizeOnDrop, Serialize, Deserialize, Eq, PartialEq, Hash)]
#[repr(transparent)]
pub struct Secret<T>(T)
where
    T: Zeroize;

impl<T> Secret<T>
where
    T: Zeroize,
{
    pub fn as_secret_ref(&self) -> &T {
        &self.0
    }

    pub fn as_secret_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T> Secret<T>
where
    T: Zeroize + Default,
{
    #[must_use]
    pub fn secret(mut self) -> T {
        mem::take(&mut self.0)
    }

    #[must_use]
    pub fn inner_into<O>(self) -> Secret<O>
    where
        O: Zeroize,
        T: Into<O>,
    {
        Secret(self.secret().into())
    }
}

impl<T> Secret<T>
where
    T: Zeroize + Clone,
{
    pub fn clone_secret(&self) -> T {
        self.0.clone()
    }
}

impl<T> From<T> for Secret<T>
where
    T: Zeroize,
{
    fn from(value: T) -> Self {
        Secret(value)
    }
}

impl From<&str> for Secret<String> {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl From<&AccessToken> for Secret<String> {
    fn from(value: &AccessToken) -> Self {
        value.secret().as_str().into()
    }
}

impl From<&RefreshToken> for Secret<String> {
    fn from(value: &RefreshToken) -> Self {
        value.secret().as_str().into()
    }
}

impl<T> Debug for Secret<T>
where
    T: Zeroize,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "[redacted]")
    }
}

impl<T> Display for Secret<T>
where
    T: Zeroize,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "[redacted]")
    }
}

impl<T> AsRef<Secret<T>> for Secret<T>
where
    T: Zeroize,
{
    fn as_ref(&self) -> &Secret<T> {
        &self
    }
}
