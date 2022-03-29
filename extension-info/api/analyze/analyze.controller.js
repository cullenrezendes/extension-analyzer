const AnalyzeService = require('../../core/analyzer/analyzer.service')

class AnalyzeController {
    static get(req, res, next) {
        res.end('hello')
    }

    static async analyze(req, res, next) {
        const link = req.body.params.link
            //console.log(req.body.params.link)
        console.log(link)


        if (!link) {
            res.status(300).json({ message: 'LINK IS EMPTY' })
            return;
        }
        try {
            const result = await AnalyzeService.analyzeLink(link)
            return res.status(200).json(result)
        } catch (error) {
            console.log(error)
            return res.status(500).json({ code: 999, message: error })
        }
    }

    static async getStaticStatus(req, res, next) {
        const analyzeStaticId = req.query.analyzeStaticId
        const result = await AnalyzeService.GetStatusStatic(analyzeStaticId)
        return res.status(200).json(result)
    }

    static async getStatusAnalyzer(req, res, next) {
	debugger;
        const analyzeStaticId = req.query.analyzeStaticId
        const analyzeDynamicId = req.query.analyzeDynamicId
        if (!analyzeStaticId || !analyzeDynamicId) {
            res.status(300).json({ message: 'LINK IS EMPTY' })
            return;
        }
        try {
            console.log('Thesis - REPORT_FINAL:', analyzeStaticId, analyzeDynamicId)
            const result = await AnalyzeService.GetStatusAnalyzer(analyzeStaticId, analyzeDynamicId)
            return res.status(200).json(result)
        } catch (error) {
            console.log(error)
            return res.status(500).json({ code: 999, message: error })
        }
    }

    static async DynamicAnalyzer(req, res, next) {
        const link = req.body.params.link
        try {
            const result = await AnalyzeService.DynamicAnalyzer(link)
            return res.status(200).json(result)
        } catch (error) {
            console.log(error)
            return res.status(500).json({ code: 999, message: error })
        }
    }
}

module.exports = AnalyzeController
