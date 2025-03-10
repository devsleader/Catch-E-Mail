import {
    validateInputEmail,
    validateEmailFormat,
    validateDnsRecords,
    validateMxRecords,
    validateSMTPConnection
} from './validator.controller.js';

export const SingleEmailChecker = async (req, res) => {
    const verification = {};
    let email;
    let domain;

    try {
        email = validateInputEmail(req.body);
        verification.inputValidation = 'passed';
    } catch (err) {
        verification.inputValidation = 'failed';
        return res.status(400).json({
            status: false,
            error: err.message,
            failedStep: 'inputValidation',
            verification,
        });
    }

    try {
        validateEmailFormat(email);
        verification.syntaxValidation = 'passed';
    } catch (err) {
        verification.syntaxValidation = 'failed';
        return res.status(400).json({
            status: false,
            error: err.message,
            failedStep: 'syntaxValidation',
            verification,
        });
    }

    try {
        domain = email.split('@')[1];
        verification.domainExtraction = 'passed';
    } catch (err) {
        verification.domainExtraction = 'failed';
        return res.status(400).json({
            status: false,
            error: 'Email failed to pass domain extraction test.',
            failedStep: 'domainExtraction',
            verification,
        });
    }

    try {
        await validateDnsRecords(domain);
        verification.dnsValidation = 'passed';
    } catch (err) {
        verification.dnsValidation = 'failed';
        return res.status(400).json({
            status: false,
            error: err.message,
            failedStep: 'dnsValidation',
            verification,
        });
    }

    try {
        await validateMxRecords(domain);
        verification.mxValidation = 'passed';
    } catch (err) {
        verification.mxValidation = 'failed';
        return res.status(400).json({
            status: false,
            error: err.message,
            failedStep: 'mxValidation',
            verification,
        });
    }

    try {
        await validateSMTPConnection(email);
        verification.smtpValidation = 'passed';
    } catch (err) {
        verification.smtpValidation = 'failed';
        return res.status(400).json({
            status: false,
            error: err.message,
            failedStep: 'smtpValidation',
            verification,
        });
    }

    return res.status(200).json({
        status: true,
        message: 'Email validation passed.',
        email,
        checkedAt: new Date().toISOString(),
        verification,
    });
};