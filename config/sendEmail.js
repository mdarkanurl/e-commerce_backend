import { resend } from "./email.js";

export const sendEmail = async ({email, subject, html}) => {
    try {
        const { data, error } = await resend.emails.send({
            from: 'E-commerce <onboarding@resend.dev>',
            to: [email],
            subject: subject,
            html: html
        });

        if(error) {
            return console.log(error);
        }

        console.log(data);
    } catch (error) {
        console.log(error)        
    }
}