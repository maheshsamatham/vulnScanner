from flask import Flask, request, jsonify, render_template, redirect, flash, send_file
import pickle
import pandas as pd

app = Flask(__name__)  # Initialize the flask App

catboost = pickle.load(open('catboost.pkl','rb'))
ExtraTreeClassifier = pickle.load(open('ExtraTreeClassifier.pkl','rb'))
gbClassifier = pickle.load(open('gbClassifier.pkl','rb'))
@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/upload')
def upload():
    return render_template('upload.html')

@app.route('/preview', methods=["POST"])
def preview():
    if request.method == 'POST':
        dataset = request.files['datasetfile']
        df = pd.read_csv(dataset, encoding='unicode_escape')
        df.set_index('Id', inplace=True)
        return render_template("preview.html", df_view=df)

@app.route('/prediction')
def prediction():
    return render_template('prediction.html')

@app.route('/predict', methods=['POST'])
def predict():
    if request.method == 'POST':
       
        try:
            duration = float(request.form['duration'])
            protocol_type = float(request.form['protocol_type'])
            flag = float(request.form['flag'])
            src_bytes = float(request.form['src_bytes'])
            dst_bytes = float(request.form['dst_bytes'])
            count = float(request.form['count'])
            srv_count = float(request.form['srv_count'])
            same_srv_rate = float(request.form['same_srv_rate'])
            diff_srv_rate = float(request.form['diff_srv_rate'])
            dst_host_same_srv_rate = float(request.form['dst_host_same_srv_rate'])
            dst_host_srv_count = float(request.form['dst_host_srv_count'])
            serror_rate = float(request.form['serror_rate'])
            srv_serror_rate = float(request.form['srv_serror_rate'])
            Model = request.form['Model']
        except ValueError:
            return "Invalid input. Please ensure all fields contain numeric values."

       
        input_variables = pd.DataFrame([[duration, protocol_type, flag, src_bytes, dst_bytes, count, srv_count, same_srv_rate,diff_srv_rate,dst_host_same_srv_rate,dst_host_srv_count,serror_rate,srv_serror_rate]],
                                       columns=['duration', 'protocol_type', 'flag', 'src_bytes', 'dst_bytes', 'count', 'srv_count', 'same_srv_rate','diff_srv_rate','dst_host_same_srv_rate','dst_host_srv_count','serror_rate','srv_serror_rate'],
                                       index=['input'])

        print(input_variables)

        
        if Model == 'CatBoostClassifier':
            predictions = catboost.predict(input_variables)
            prediction = predictions[0]
        elif Model == 'ExtraTreeClassifier':
            prediction = ExtraTreeClassifier.predict(input_variables)
        elif Model == 'GradientBoostingClassifier':
            prediction = gbClassifier.predict(input_variables)
        else:
            return "Invalid model selected."

        print(prediction) 
        outputs = prediction[0] 
        print(outputs)
        # results = "Yes Diagnosis" if outputs == 1 else "No Diagnosis"

    return render_template('result.html', 
                           prediction_text=outputs, 
                           model=Model, 
                           duration=duration, 
                           protocol_type=protocol_type, 
                           flag=flag, 
                           src_bytes=src_bytes, 
                           dst_bytes=dst_bytes, 
                           count=count, 
                           srv_count=srv_count, 
                           same_srv_rate=same_srv_rate,
                           diff_srv_rate=diff_srv_rate,
                           dst_host_same_srv_rate=dst_host_same_srv_rate,
                           dst_host_srv_count=dst_host_srv_count,
                           serror_rate=serror_rate,
                           srv_serror_rate=srv_serror_rate)


@app.route('/chart')
def chart():
    return render_template('chart.html')

@app.route('/performance')
def performance():
    return render_template('performance.html')

if __name__ == "__main__":
    app.run(debug=True)
