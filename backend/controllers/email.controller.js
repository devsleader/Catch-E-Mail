import { validateInputEmail, validateEmailFormat, validateDnsRecords, validateMxRecords } from './validator.controller.js'

export const SingleEmailChecker = async (req, res) => {
    try {
        const email = validateInputEmail(req.body);

        validateEmailFormat(email);

        const domain = email.split('@')[1];

        await validateDnsRecords(domain);

        await validateMxRecords(domain);

        return res.status(200).json({
            status: true,
            message: 'Email validation passed.',
            email,
            checkedAt: new Date().toISOString(),
            verification: {
                inputValidation: 'passed',
                syntaxValidation: 'passed',
                dnsValidation: 'passed',
                mxValidation: 'passed',
                smtpValidation: 'passed'
            }
        });
    } catch (err) {
        return res.status(400).json({
            status: false,
            error: err.message,
            failedStep: err.step || 'unknown'
        });
    }
};