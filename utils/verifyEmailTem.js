export const verifyEmailTem = ({name, url}) => {
    try {
        return `
        <p> Dear ${name} </p>
        <p> Welcome to our app click here 👇 to verify email </p>
        <a href=${url}>
        Verify email
        </a>`
    } catch (error) {
        console.log(error)
    }
}