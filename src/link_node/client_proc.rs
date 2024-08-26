use haiyuu::Process;

pub struct ClientProcess {}

impl Process for ClientProcess {
    type Message = ();

    type Output = ();

    async fn run(&mut self, mailbox: &mut haiyuu::Mailbox<Self>) -> Self::Output {
        todo!()
    }
}
