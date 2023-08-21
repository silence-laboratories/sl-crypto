use std::fmt;

use crate::message::{Message, MsgId};

pub trait OutputQueue {
    /// Inform the message relay subsystem that we are waiting
    /// for a message with given ID for at most TTL seconds.
    fn wait(&mut self, msg_id: &MsgId, ttl: u32);

    /// Publish message. Send it a message relay.
    fn publish(&mut self, msg: Vec<u8>);
}

pub trait Env: OutputQueue {}

impl<T: OutputQueue> Env for T {}

#[derive(Debug)]
pub struct WaitQueue<T> {
    queue: Vec<(MsgId, T)>,
}

impl<T> WaitQueue<T> {
    pub fn new() -> Self {
        Self {
            queue: Vec::with_capacity(2),
        }
    }

    /// Associate ID with the DATUM
    pub fn wait(&mut self, id: &MsgId, datum: T) {
        self.queue.push((*id, datum));
    }

    pub fn remove(&mut self, id: &MsgId) -> Option<T> {
        let idx = self.queue.iter().position(|(msg_id, _)| msg_id == id)?;

        let (_, data) = self.queue.swap_remove(idx);

        Some(data)
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

/// Result of process of an input message by some round S.
pub enum Output<S: State> {
    /// Stay at the same round, need more messages
    Loop(S),

    /// Move to next state
    Next(S::Next),
}

pub type StateResult<S> =
    core::result::Result<Output<S>, <S as State>::Error>;

/// Represents a MPC round. This is a back block of MPC protocols.
pub trait State: Sized {
    type Next;
    type Error: fmt::Debug;

    fn process(
        self,
        env: &mut dyn Env,
        msg: &mut Message,
    ) -> Result<Output<Self>, Self::Error>;
}

/// Represents sequence of one or more states of MPC protocol.
pub trait Step: Sized {
    /// State of this step
    type State: State;

    /// Type of final result of a sequence of steps.
    type Result;

    /// A possible error
    type Error: fmt::Debug;

    /// Create a Step from a given State.
    fn create(state: Self::State) -> Self;

    /// Execute a Step.
    fn step(
        &mut self,
        env: &mut dyn Env,
        msg: &mut Message,
    ) -> Status<Self::Result, Self::Error>;
}

/// Result of execution of one step of a MPC protocol
#[derive(Debug)]
pub enum Status<T, E> {
    /// Pending for more messages
    Pending,

    /// Already finished
    Finished,

    /// The protocol returned final value
    Fini(T),

    /// The protocol return an error
    Error(E),
}

/// Final step of a protocol
pub struct Final<T: State> {
    state: Option<T>,
}

impl<T: State> Step for Final<T> {
    type State = T;
    type Result = T::Next;
    type Error = T::Error;

    fn create(state: T) -> Self {
        Self { state: Some(state) }
    }

    fn step(
        &mut self,
        env: &mut dyn Env,
        msg: &mut Message,
    ) -> Status<Self::Result, Self::Error> {
        match self.state.take() {
            None => Status::Finished,
            Some(state) => match state.process(env, msg) {
                Ok(Output::Loop(new_state)) => {
                    self.state = Some(new_state);
                    Status::Pending
                }
                Ok(Output::Next(next)) => Status::Fini(next),
                Err(err) => Status::Error(err),
            },
        }
    }
}

/// Given a sequence of Steps. Create a new Step by prepending a given
/// State.
pub enum Next<T: State, Steps> {
    P(Option<T>),
    N(Steps),
}

impl<T, Steps> Step for Next<T, Steps>
where
    T: State<Error = Steps::Error, Next = Steps::State>,
    Steps: Step,
{
    type State = T;
    type Result = Steps::Result;
    type Error = Steps::Error;

    fn create(state: T) -> Self {
        Self::P(Some(state))
    }

    fn step(
        &mut self,
        env: &mut dyn Env,
        msg: &mut Message,
    ) -> Status<Self::Result, Self::Error> {
        match self {
            Next::N(next) => next.step(env, msg),
            Next::P(None) => Status::Finished,
            Next::P(state) => {
                let state = state.take().unwrap();

                match state.process(env, msg) {
                    Err(err) => Status::Error(err),
                    Ok(Output::Next(next)) => {
                        *self = Next::N(Steps::create(next));
                        Status::Pending
                    }
                    Ok(Output::Loop(new_state)) => {
                        *self = Next::P(Some(new_state));
                        Status::Pending
                    }
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(dead_code)]
mod tests {
    use super::*;

    #[derive(Clone)]
    pub struct DummyEnv;

    impl OutputQueue for DummyEnv {
        fn wait(&mut self, _msg_id: &MsgId, _ttl: u32) {}
        fn publish(&mut self, _msg: Vec<u8>) {}
    }

    #[derive(Debug)]
    pub struct Err1;

    pub struct S1;
    pub struct S2;
    pub struct S3;

    impl State for S1 {
        type Next = S2;
        type Error = Err1;

        fn process(
            self,
            _env: &mut dyn Env,
            _msg: &mut Message,
        ) -> StateResult<Self> {
            Ok(Output::Loop(self))
        }
    }

    impl State for S2 {
        type Next = S3;
        type Error = Err1;

        fn process(
            self,
            _env: &mut dyn Env,
            _msg: &mut Message,
        ) -> StateResult<Self> {
            Ok(Output::Loop(self))
        }
    }

    impl State for S3 {
        type Next = ();
        type Error = Err1;

        fn process(
            self,
            _env: &mut dyn Env,
            _msg: &mut Message,
        ) -> StateResult<Self> {
            Ok(Output::Loop(self))
        }
    }

    pub type Session = Next<S1, Next<S2, Final<S3>>>;

    pub fn test_session(sess: &mut Session) {
        let mut e = DummyEnv;
        loop {
            sess.step(&mut e, &mut Message::from_buffer(&mut []).unwrap());
        }
    }

    #[test]
    fn run_poroto() {}
}
