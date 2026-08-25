const fs = require('fs');
const path = require('path');
const mailService = require('../system/mailer/nodeMailer.service');

const emailNotificationService = {
    sendReceiptEmail : async (appName, senderEmail, customerName, service, amount, total) =>
    {
        try
        {
            console.log('email send fired.');
            fs.readFile(path.resolve('public/receipt.html'), 'utf8', (err, data) =>
            {
                if (err)
                {
                    console.log(err);
                    return;
                }

                console.log(appName, customerName, amount, total);

                const htmlBody = data.replace("{app_name}", appName)
                    .replace("{customer_name}", customerName)
                    // .replace("{invoice_number}", new Date().getTime().toString())
                    .replace("{invoice_number}", 'sdsd')
                    // .replace("{date}", new Date().toISOString().slice(0, 10))
                    .replace("{date}", 'sdsd')
                    .replace('{amount}', amount)
                    .replace('{service}', service)
                    .replace("{total}", total);

                mailService.send(senderEmail, `${appName} E-Receipt`, htmlBody)
                    .catch((mailErr) => console.log('receipt email failed (non-fatal):', mailErr.message));
            });
        }
        catch (e)
        {
            // Receipt email is a best-effort notification; never fail the payment because of it.
            console.log('sendReceiptEmail failed (non-fatal):', e.message);
        }
    },
};

module.exports = emailNotificationService;
