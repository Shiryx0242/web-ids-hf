FROM python:3.9

RUN useradd -m -u 1000 user
USER user
ENV HOME=/home/user \
	PATH=/home/user/.local/bin:$PATH
WORKDIR $HOME/app
COPY --chown=user . $HOME/app
RUN pip install --no-cache-dir -r requirements.txt
RUN mkdir -p /tmp && chmod 777 /tmp
ENV VERCEL=1 
EXPOSE 7860
CMD ["gunicorn", "-b", "0.0.0.0:7860", "--timeout", "120", "app:app"]
