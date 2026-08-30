use cot::Project;

struct MyProject;
impl Project for MyProject {
    type User = cot::auth::NoUser;
}

#[cot::main]
fn main() -> impl Project {
    std::process::exit(0);

    #[expect(unreachable_code)]
    MyProject
}
