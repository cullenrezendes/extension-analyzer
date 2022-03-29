const path = require('path')
const util = require('util')
const fs = require('fs')
const execFile = util.promisify(require('child_process').execFile);
const { spawn } = require('child_process')
const MongoClient = require('mongodb').MongoClient;
const ObjectId = require('mongodb').ObjectId; 
const assert = require('assert');


class AnalyzerService {
    static async analyzeLink(link) {
        const list_parse_link = link.split("/");
        const extension_ID_with_split = list_parse_link[list_parse_link.length-1];
        const extension_ID = extension_ID_with_split.split("?")[0];
        const url = 'mongodb://localhost:27017';
            // Database Name
        const dbName = 'Thesis';
        const client = await MongoClient.connect(url);
        const db = client.db(dbName);
        const collection = db.collection('Analyzer');
        const report_static_check = await collection.countDocuments({id:extension_ID})
        if(report_static_check > 0)
        {
            const outputData = await collection.findOne({id:extension_ID}); 
            // const outputDocument = outputData["_id"]
            // console.log("ID Static:",outputDocument)
            return outputData
        }
        const outputDocument = await collection.insertOne({
            status: false
        })
        const analyzePyPath = path.resolve(__dirname, 'analyzer.py')
        // let execF = execFile('python3', [analyzePyPath, '-l', link, '-mid', outputDocument._id], { shell: true, cwd: path.resolve(__dirname) }) //stdout == Output(Ext)
        spawn('python3', [analyzePyPath, '-l', link, '-mid', outputDocument.ops[0]._id], { shell: true, cwd: path.resolve(__dirname) }) //stdout == Output(Ext)
        // let resultString = '';
        // execF.stdout.on('data', (data) => {
        //     resultString += data
        // });

        // execF.stdout.on('close', () => {
        //     resultString = resultString.replace(/\r?\n|\r/g, "")
        // })

        return outputDocument.ops[0]
        
        // if (stderr) {
        //     throw new Error("Error at analyze ext. Analyzer.service.js")
        // } else {
        //     stdout = stdout.replace(/\r?\n|\r/g, "")
        //         // Connection URL
            
        //     try {
        //         console.log('Stdout', stdout)
        //         const outputData = await collection.findOne({ id: stdout });
        //         //console.log('Output', outputData)
        //         client.close();
        //         return { data: outputData }
        //     } catch (err) {
        //         console.log('Err' + err)
        //         return { data: null }
        //     }

        //     // const outputFilePath = path.resolve(__dirname,stdout)
        //     // const outputFileData = fs.readFileSync(outputFilePath).toString()
        //     //need to understand this
        // }
    }

    static async GetStatusStatic(analyzeStaticId) {
        const url = 'mongodb://localhost:27017';
        // Database Name
        const dbName = 'Thesis';
        try {
            const client = await MongoClient.connect(url);
            const db = client.db(dbName);
            const collection = db.collection('Analyzer');

            const outputData = await collection.findOne({ _id: ObjectId(analyzeStaticId) });
            if (outputData.status) {
                return outputData
            } else {
                return null
            }

        } catch (e) {
            return null
        }
    }

    static async GetStatusAnalyzer(analyzeStaticId, analyzeDynamicId) {
	debugger;
        const url = 'mongodb://127.0.0.1:27017';
        // Database Name
        const dbName = 'Thesis';
        const dbName2 = 'ChromeExtension';
        try {
            const client = await MongoClient.connect(url);
            const db = client.db(dbName);
            const collection = db.collection('Analyzer');

            const db2 = client.db(dbName2);
            const collection_report = db2.collection('REPORT_FINAL');
            const collection_dns = db2.collection('DNS');
            const collection_network = db2.collection('NETWORK');

            // console.log('Stdout', stdout)
            const outputData = await collection.findOne({ _id: ObjectId(analyzeStaticId) });

            const outputData_report = await collection_report.findOne({ _id: ObjectId(analyzeDynamicId) });
            //console.log('DDDDD', outputData, outputData_report)
            if(outputData.status && outputData_report.status) {
                const idDynamic = outputData_report.id
                const outputData_dns = await collection_dns.find({ idx: idDynamic }).toArray()
                const outputData_network = await collection_network.findOne({ idx: idDynamic });
                return {
                    static: outputData,
                    dynamic: {
                        Report: outputData_report,
                        Network: outputData_network,
                        Dns: outputData_dns
                    }
                }
            }
            client.close();

            return null            
        } catch (err) {
            console.log('Err' + err)
            return null
        }
    }

    static async DynamicAnalyzer(link) {
        const list_parse_link = link.split("/");
        const extension_ID_with_split = list_parse_link[list_parse_link.length-1];
        const extension_ID = extension_ID_with_split.split("?")[0];
        const url = 'mongodb://localhost:27017';
        // Database Name
        const dbName = 'ChromeExtension';
        const client = await MongoClient.connect(url);
        const db = client.db(dbName);
        const collection_report = db.collection('REPORT_FINAL');
        const report_dynamic_check = await collection_report.countDocuments({id:extension_ID})
        if(report_dynamic_check > 0)
        {
            const outputData = await collection_report.findOne({id:extension_ID}); 
            // const outputDocument = outputData["_id"]
            // console.log("ID Dynamic:",outputDocument)
            return outputData
        }
        const outputData_report = await collection_report.insertOne({ status: false });
        debugger;
        const analyzePyPath = path.resolve(__dirname, 'source/sandbox/sandbox.py')
        var process = spawn('python3', [analyzePyPath, '-l', link, '-mid', outputData_report.ops[0]._id], { shell: true, cwd: path.resolve(__dirname) }) //stdout == Output(Ext)
        

        return outputData_report.ops[0]
        
        // if (stderr) {
        //     throw new Error("Error at analyze ext. Analyzer.service.js")
        // } else {
        //     var searchTerm = "@@@"
        //     stdout = stdout.replace(/\r?\n|\r/g, "");
        //     console.log("DynamicAnalyzer stdout:" + stdout)
        //     if (stdout == "None") {
        //         return { data: null }
        //     }

        //     const regx = /@@@(.+)@@@/
        //     const value = regx.exec(stdout)[1];
        //     //console.log(value)
        //     //console.log(stdout)
        //     // Connection URL

        //     try {
                
               
        //         const outputData_report = await collection_report.findOne({ id: value });
        //         const outputData_dns = await collection_dns.find({ idx: value }).toArray()
        //         const outputData_network = await collection_network.findOne({ idx: value });
        //         let outputData = {}
        //         outputData.Report = outputData_report
        //         outputData.Network = outputData_network
        //         outputData.Dns = outputData_dns
        //             //console.log(outputData)
        //         client.close();
        //         return { data: outputData }
        //     } catch (err) {
        //         console.log('Err' + err)
        //         return { data: null }
        //     }

        //     // const outputFilePath = path.resolve(__dirname,stdout)
        //     // const outputFileData = fs.readFileSync(outputFilePath).toString()
        //     //need to understand this
        // }
    }
}

module.exports = AnalyzerService
