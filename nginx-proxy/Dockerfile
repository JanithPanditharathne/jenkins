FROM nginx:alpine

LABEL maintainer="Janith Hasantha Panditharathne"

# Envplate to dynamically change nginx configurations
RUN curl -sLo /usr/local/bin/ep https://github.com/kreuzwerker/envplate/releases/download/v0.0.8/ep-linux && \
    chmod +x /usr/local/bin/ep

# Install packages
RUN apk add --no-cache ca-certificates tzdata

# Copy nginx configs
COPY nginx /etc/nginx

# Add permissions for nginx user
RUN chown -R nginx:nginx /etc/nginx /var/cache/nginx && \
    chmod -R o-rwx /etc/nginx /var/cache/nginx && \
    touch /var/run/nginx.pid && \
    chown -R nginx:nginx /var/run/nginx.pid && \
    chown -R nginx:nginx /var/log/nginx

USER nginx

WORKDIR /etc/nginx/conf.d

EXPOSE 8080 8443

CMD ["/usr/local/bin/ep", "-v", "/etc/nginx/conf.d/*.conf", "--", "/usr/sbin/nginx", "-g", "daemon off;"]
