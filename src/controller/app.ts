import express, {Request, Response} from 'express'
import cors from 'cors'
import dotenv from 'dotenv'

dotenv.config()

const app = express()
app.use(express.json())
app.use(cors())
app.listen(3003, ()=>{
    console.log(`Server is running as http://localhost:3003`)
})

export default app