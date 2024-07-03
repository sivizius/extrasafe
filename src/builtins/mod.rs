//! Built-in [`RuleSet`](crate::RuleSet)s

/// Implement `allow_*`-methods.
///
/// See e.g. `time.mod` and `user_id.mod`.
///
/// NOTE: Follow the `@labels`.
macro_rules! allow {
    (
        $(#[$attr:meta])*
        $vis:vis fn $method:ident($self:ident) {
            $($inner:tt)*
        }
    ) => {
        allow! {
            @impl_outer ()
            $(#[$attr])*
            $vis fn $method($self) -> Self {
                $($inner)*
            }
        }
    };

    (
        $(#[$attr:meta])*
        $vis:vis unsafe fn $method:ident($self:ident) {
            $($inner:tt)*
        }
    ) => {
        allow! {
            @impl_outer (unsafe)
            $(#[$attr])*
            $vis fn $method($self) -> YesReally<Self> {
                $($inner)*
            }
        }
    };

    (
        $(
            $(#[$attr:meta])*
            $vis:vis $($outer:ident)+($self:ident) { $($inner:tt)* }
        )*
    ) => {
        $(
            allow! {
                $(#[$attr])*
                $vis $($outer)+($self) {
                    $($inner)*
                }
            }
        )*
    };

    (
        @impl_outer ($($unsafe:ident)?)
        $(#[$outer_attr:meta])*
        $outer_vis:vis fn $outer_method:ident($self:ident) -> $output:ty {
            $(
                $(#[$inner_attr:meta])*
                $inner_vis:vis $($inner:ident)+ ($syscall:ident);
            )*
        }
    ) => {
        $(#[$outer_attr])*
        $outer_vis fn $outer_method($self) -> $output {
            allow! { @call_inner_block $($unsafe)? $self { $(($($inner)+))* } }
        }

        allow! {
            @impl_inner_block $($unsafe)? {
                $(
                    $(#[$inner_attr])*
                    $inner_vis $($inner)+ ($syscall)
                )*
            }
        }
    };

    ( @call_inner_block $self:ident { $(($($inner:ident)+))* } ) => {
        let this = $self;
        $( allow! { @call_inner this: $($inner)+ } )*
        this
    };

    ( @call_inner_block unsafe $self:ident { $(($($inner:ident)+))* } ) => {
        let this = $self;
        $( allow! { @call_inner this: unsafe $($inner)+ } )*
        YesReally::new(this)
    };

    ( @call_inner $this:ident: fn $method:ident ) => {
        let $this = $this.$method();
    };

    ( @call_inner $this:ident: unsafe $(unsafe)? fn $method:ident ) => {
        let $this = $this.$method().yes_really();
    };

    (
        @impl_inner_block {
            $(
                $(#[$attr:meta])*
                $vis:vis $($inner:ident)+($syscall:ident)
            )*
        }
    ) => {
        $(
            allow! {
                @impl_inner
                $(#[$attr])*
                $vis $($inner)+($syscall)
            }
        )*
    };

    (
        @impl_inner_block
        unsafe {
            $(
                $(#[$attr:meta])*
                $vis:vis $(unsafe)? fn $method:ident($syscall:ident)
            )*
        }
    ) => {
        $(
            allow! {
                @impl_inner
                $(#[$attr])*
                $vis unsafe fn $method($syscall)
            }
        )*
    };

    (
        @impl_inner
        $(#[$attr:meta])*
        $vis:vis fn $method:ident($syscall:ident)
    ) => {
        $(#[$attr])*
        $vis fn $method(mut self) -> Self {
            let _ = self.syscalls.insert(syscalls::Sysno::$syscall);
            self
        }
    };

    (
        @impl_inner
        $(#[$attr:meta])*
        $vis:vis unsafe fn $method:ident($syscall:ident)
    ) => {
        $(#[$attr])*
        $vis fn $method(mut self) -> YesReally<Self> {
            let _ = self.syscalls.insert(syscalls::Sysno::$syscall);
            YesReally::new(self)
        }
    };
}

pub mod basic;
pub mod danger_zone;
pub mod kill;
pub mod network;
pub mod pipes;
pub mod systemio;
pub mod time;
pub mod truncate;
pub mod user_id;

pub use self::{
    basic::BasicCapabilities,
    kill::Kill,
    network::{Netlink, Networking, SocketPair},
    systemio::SystemIO,
    time::Time,
    truncate::Truncate,
    user_id::UserId,
};

/// A struct whose purpose is to make you read the documentation for the function you're calling.
/// If you're reading this, go read the documentation for the function that is returning this
/// object.
#[must_use]
pub struct YesReally<T> {
    inner: T,
}

impl<T> YesReally<T> {
    /// Confirm you really wanted to call the function and return its result.
    pub fn yes_really(self) -> T {
        self.inner
    }

    /// Make a [`YesReally`].
    pub fn new(inner: T) -> YesReally<T> {
        YesReally { inner }
    }
}
