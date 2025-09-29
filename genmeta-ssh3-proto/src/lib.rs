mod entry_guard;

// TODO: 版本化
pub mod cbor_codec;
pub mod forward;
pub mod listener;
pub mod messages;
pub mod mux;
pub mod socks;

pub mod v0 {
    use std::sync::LazyLock;

    use http::Method;

    pub mod forward {
        pub use crate::forward::*;
    }

    pub mod listener {
        pub use crate::listener::*;
    }

    pub mod messages {
        pub use crate::messages::*;
    }

    pub mod mux {
        pub use crate::mux::*;
    }

    pub mod socks {
        pub use crate::socks::*;
    }

    pub static METHOD: LazyLock<Method> = LazyLock::new(|| http::Method::PUT);
}
